module dinst.dinst;

import std.stdio;
import std.traits;
import dinst.patch;

private enum bool isMethod(alias func) = (false
	|| is(__traits(parent, func) == struct)
	|| is(__traits(parent, func) == class)
	|| is(__traits(parent, func) == interface)
	|| is(__traits(parent, func) == union)
	) && !__traits(isStaticFunction, func);

private template ParentRef(alias func)
{
	static if (is(__traits(parent, func) == struct)
		|| is(__traits(parent, func) == union))
	{
		alias ParentType = __traits(parent, func);
		alias ParentRef = ParentType*;
	}
	else static if (is(__traits(parent, func) == class)
		|| is(__traits(parent, func) == interface))
	{
		alias ParentRef = __traits(parent, func);
	}
	else
	{
		alias ParentRef = void*;
	}
}

struct HookData
{
private:
	import core.sync.mutex;
	void*     _original;
	void*     _hookTarget;
	void*     _trampoline;
	size_t    _trampolineSize;
	Mutex     _mutex;
	size_t    _counter;
	void delegate() _callback;
	
	void _createTrampolineMemory()
	{
		version (Windows)
		{
			import core.sys.windows.windows;
			_trampoline = VirtualAlloc(null, _trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		else version (Posix)
		{
			import core.sys.posix.sys.mman;
			import core.sys.posix.sys.types;
			_trampoline = mmap(null, _trampolineSize,
				PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
		}
		else static assert(0);
	}
	
	bool _createJmp64(void* where, void* target)
	{
		// 64bitジャンプ
		auto stolen = determineStolenBytes(where, 12);
		if (stolen.size == 0)
			return false;
		if (stolen.isJmp)
		{
			_trampolineSize = 12;
			_createTrampolineMemory();
			if (!createTrampoline64Jmp(stolen.addr, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
			if (!writeAbsJump(where, target))
				return false;
			return true;
		}
		_trampolineSize = stolen.size + 12;
		_createTrampolineMemory();
		if (stolen.isRet)
		{
			if (!createTrampoline64Ret(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
			if (!writeAbsJump(where, target))
				return false;
			return true;
		}
		if (!createTrampoline64(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
			return false;
		if (!writeAbsJump(where, target))
			return false;
		return true;
	}
	
	bool _createJmp32(void* where, void* target)
	{
		// 32bitジャンプ
		auto stolen = determineStolenBytes(where, 5);
		if (stolen.size == 0)
			return false;
		if (stolen.isJmp)
		{
			version (X86_64)
			{
				_trampolineSize = 12;
			}
			else version (X86)
			{
				_trampolineSize = 5;
			}
			_createTrampolineMemory();
			if (!createTrampoline64Jmp(stolen.addr, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
			if (!writeAbsJump(where, target))
				return false;
			return true;
		}
		version (X86_64)
		{
			_trampolineSize = stolen.size + 12;
		}
		else version (X86)
		{
			_trampolineSize = stolen.size + 5;
		}
		else static assert(0);
		_createTrampolineMemory();
		version (X86_64)
		{
			if (!createTrampoline64(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
		}
		else version (X86)
		{
			if (!createTrampoline32(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
		}
		else static assert(0);
		
		if (!writeRelJump(where, target))
			return false;
		return true;
	}
	
	bool _create(void* where, void* target)
	{
		_original   = where;
		_hookTarget = target;
		size_t diffAddress = where < target ? target - where : where - target;
		
		if (diffAddress > int.max)
		{
			if (!_createJmp64(where, target))
				return false;
		}
		else
		{
			if (!_createJmp32(where, target))
				return false;
		}
		_mutex = new Mutex;
		return true;
	}
	
	void _clearState()
	{
		_callback = null;
		_counter = 0;
	}
}

private __gshared HookData[string] g_hooks;

private ReturnType!func _generalHook(alias func)(Parameters!func args)
if (!isMethod!func)
{
	auto hook = func.mangleof in g_hooks;
	assert(hook);
	hook._counter++;
	alias DgType = ReturnType!func delegate(Parameters!func);
	if (hook._callback !is null)
		return (*cast(DgType*)(&hook._callback))(args);
	return (cast(ReturnType!func function(Parameters!func))hook._trampoline)(args);
}

version (LDC)
{
	private ReturnType!func _generalHook(alias func)(ParentRef!func parent, Parameters!func args)
	if (isMethod!func)
	{
		auto hook = func.mangleof in g_hooks;
		assert(hook);
		hook._counter++;
		alias DgType = ReturnType!func delegate(ParentRef!func, Parameters!func);
		if (hook._callback !is null)
			return (*cast(DgType*)(&hook._callback))(parent, args);
		return (cast(ReturnType!func function(ParentRef!func, Parameters!func))hook._trampoline)(parent, args);
	}
}
else
{
	private ReturnType!func _generalHook(alias func)(Parameters!func args, ParentRef!func parent)
	if (isMethod!func)
	{
		auto hook = func.mangleof in g_hooks;
		assert(hook);
		hook._counter++;
		alias DgType = ReturnType!func delegate(Parameters!func, ParentRef!func);
		if (hook._callback !is null)
			return (*cast(DgType*)(&hook._callback))(args, parent);
		return (cast(ReturnType!func function(Parameters!func, ParentRef!func))hook._trampoline)(args, parent);
	}
}

/*******************************************************************************
 * 
 */
bool createHook(alias func)()
{
	if (func.mangleof in g_hooks)
		return true;
	HookData dat;
	if (!dat._create(&func, &(_generalHook!func)))
		return false;
	g_hooks[func.mangleof] = dat;
	return true;
}

/*******************************************************************************
 * 
 */
void setHookFunc(alias func)(ReturnType!func delegate(Parameters!func) dg)
if (!isMethod!func)
{
	auto hook = func.mangleof in g_hooks;
	assert(hook);
	alias DgType = void delegate();
	synchronized (hook._mutex)
		hook._callback = *cast(DgType*)cast(void*)&dg;
}
/// ditto
void setHookFunc(alias func)(ReturnType!func delegate(ParentRef!func, Parameters!func) dg)
if (isMethod!func)
{
	auto hook = func.mangleof in g_hooks;
	assert(hook);
	alias DgType = void delegate();
	version (LDC)
		alias callback = dg;
	else
		auto callback = delegate ReturnType!func (Parameters!func args, ParentRef!func p) => dg(p, args);
	synchronized (hook._mutex)
		hook._callback = *cast(DgType*)cast(void*)&callback;
}
/// ditto
void setHookFunc(alias func)(ReturnType!func function(Parameters!func) dg)
if (!isMethod!func)
{
	import std.functional;
	setHookFunc!func(toDelegate(dg));
}
/// ditto
void setHookFunc(alias func)(ReturnType!func function(ParentRef!func, Parameters!func) dg)
if (isMethod!func)
{
	import std.functional;
	setHookFunc!func(toDelegate(dg));
}

/*******************************************************************************
 * 
 */
void clearHookState(alias func)()
{
	auto hook = func.mangleof in g_hooks;
	assert(hook);
	synchronized (hook._mutex)
		hook._clearState();
}

/*******************************************************************************
 * 
 */
ReturnType!func callHookOriginal(alias func)(Parameters!func args)
{
	auto hook = func.mangleof in g_hooks;
	assert(hook);
	alias Fn = ReturnType!func function(Parameters!func);
	Fn fn;
	synchronized (hook._mutex)
		fn = cast(Fn)hook._trampoline;
	return fn(args);
}



/*******************************************************************************
 * 
 */
struct SetupHook(alias func)
{
private:
	import core.sync.mutex;
	Mutex _mutex;
	void lockMutex()
	{
		if (_mutex)
			return;
		auto hook = func.mangleof in g_hooks;
		assert(hook);
		_mutex = hook._mutex;
		_mutex.lock();
	}
public:
	shared static this() @trusted
	{
		auto res = createHook!func();
		assert(res, "Failed to setup a hook: " ~ hook.mangleof);
	}
	///
	~this() @trusted
	{
		clearHookState!func();
		if (_mutex)
			_mutex.unlock();
	}
	///
	ReturnType!func callOrig(Parameters!func args) @trusted
	{
		return callHookOriginal!func(args);
	}
	
	///
	void hook()(ReturnType!func function(Parameters!func) fn) @trusted
	if (!isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(fn);
	}
	/// ditto
	void hook()(ReturnType!func function(ParentRef!func, Parameters!func) fn) @trusted
	if (isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(fn);
	}
	/// ditto
	void hook()(ReturnType!func delegate(Parameters!func) dg) @trusted
	if (!isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(dg);
	}
	/// ditto
	void hook()(ReturnType!func delegate(ParentRef!func, Parameters!func) dg) @trusted
	if (isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(dg);
	}
}

/// ditto
SetupHook!func setupHook(alias func)() @trusted
{
	return SetupHook!func();
}


@safe unittest
{
	static int foo(int a, int b)
	{
		return a + b;
	}
	static int myFoo(int a, int b)
	{
		return a * b;
	}
	auto hookFoo = setupHook!foo;
	
	assert(foo(3, 5) == 8);
	hookFoo.hook(&myFoo);
	assert(foo(3, 5) == 15);
	hookFoo.hook((int a, int b){
		return a + b + a * b;
	});
	assert(foo(3, 5) == 23);
	assert(hookFoo.callOrig(3, 5) == 8);
}


@safe unittest
{
	class C
	{
		int x;
		int foo(int a, int b) @safe
		{
			return a + b + x;
		}
	}
	auto hookFoo = setupHook!(C.foo);
	auto c = new C;
	c.x = 10;
	assert(c.foo(3, 5) == 18);
	static int myFoo(C self, int a, int b)
	{
		return a * b + self.x;
	}
	hookFoo.hook(&myFoo);
	assert(c.foo(3, 5) == 25);
}
