module dinst.dinst;

import std.stdio;
import std.traits;
import dinst.patch;
import dinst.arch;

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
				_createTrampolineMemory();
				if (!createTrampoline64Jmp(stolen.addr, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
					return false;
				if (!writeAbsJump(where, target))
					return false;
			}
			else version (X86)
			{
				_trampolineSize = 10;
				_createTrampolineMemory();
				if (!createTrampoline32Jmp(stolen.addr, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
					return false;
				if (!writeRelJump(where, target))
					return false;
			}
			return true;
		}
		version (X86_64)
		{
			_trampolineSize = stolen.size + 12;
			_createTrampolineMemory();
			if (!createTrampoline64(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
			if (!writeRelJump(where, target))
				return false;
		}
		else version (X86)
		{
			_trampolineSize = stolen.size + 10;
			_createTrampolineMemory();
			if (!createTrampoline32(where, stolen.size, (cast(ubyte*)_trampoline)[0.._trampolineSize]))
				return false;
			if (!writeRelJump(where, target))
				return false;
		}
		else static assert(0);
		
		return true;
	}
	
	bool _create(void* where, void* target)
	{
		_original   = where;
		_hookTarget = target;
		// _mutex の確保(GCアロケーション)は、実際にバイナリへパッチを
		// 当てる「前」に行う。
		//
		// (これを後回しにすると、`new Mutex` が引き金となってGCの
		//  遅延初期化(gc_init_nothrow)が走った際、GC自身の初期化処理が
		//  内部で calloc()/malloc() 等を呼び出すことがあり、その時点で
		//  既にフック対象の関数がパッチ済みだと、パッチしたばかりの
		//  関数の呼び出し中にGC初期化処理が再入してしまい、
		//  "Cannot initialize the garbage collector" で異常終了する。
		//  free()のシャットダウン時と同様の「GC自身が依存する関数を
		//  フックする際に生じる、鶏と卵の問題」の別パターンである)
		_mutex = new Mutex;
		version (X86)
		{
			if (!_createJmp32(where, target))
				return false;
		}
		else version (X86_64)
		{
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
		}
		else static assert(0);
		return true;
	}
	
	void _clearState()
	{
		_callback = null;
		_counter = 0;
	}
}

/*******************************************************************************
 * フック情報の登録先
 *
 * 【背景】GC自身が(druntimeの終了処理 `gc_term()` の中で、自分が
 * 使っていたメモリプールを解放するために)内部的に `free()`
 * (場合によっては `malloc`/`calloc`/`realloc` も)を呼び出すことがある。
 * Windows実機での調査により、これは
 *   gc_term -> ConservativeGC.__dtor -> Gcx.Dtor -> Pool.Dtor -> free()
 * という、**GC自身の後始末処理の真っ最中**に発生することが判明した。
 *
 * もしフック情報の登録先(従来の `g_hooks`)がGC管理メモリ上の
 * 連想配列だと、このタイミングで free() 経由の _generalHook!free が
 * それを参照しようとした際、まさにその参照先のメモリ(GCのプール)が
 * GC自身によって破棄されている最中であるため、不正なメモリアクセス
 * (Windowsでは0xC0000005、Linuxでは類似のセグメンテーション違反)を
 * 起こしてクラッシュする。
 *
 * この問題が起こりうるのは、**GC自身が内部で依存している
 * malloc/free/calloc/realloc をフックした場合に限られる**。
 * それ以外の通常の関数(D関数や、GCと無関係な任意のC関数)を
 * フックする分には、このような問題は起こらない。
 *
 * そこで、フック情報の登録先を用途に応じて2種類使い分ける:
 *
 * - `g_hooks`(連想配列、GC管理メモリ): malloc/free/calloc/realloc
 *   **以外**の通常の関数用。従来通り、登録数に制限は無い。
 * - `g_allocatorHookSlots`(固定長配列、GC/malloc/freeいずれにも
 *   依存しない静的データ領域): malloc/free/calloc/realloc
 *   **専用**。GCや(フック対象である)アロケータ自体の生存状態に
 *   関わらず、プログラムの実行中いつでも安全に参照できる。
 *   これら4関数を同時にすべてフックしても4エントリしか使わないため、
 *   スロット数はごく小さくてよい。
 */
private __gshared HookData[string] g_hooks;

/// funcが「GC自身が内部で依存しうる」libcのアロケータ関数かどうか
/// (core.stdc.stdlib の malloc/free のみが対象)
///
/// NOTE: calloc/realloc も同様の理由で対象に加えることを検討したが、
/// 調査の過程で calloc は「thread_joinAll 経由の別の異なる問題」を
/// 単独で引き起こすことが分かった(realloc は未検証)。これは
/// 今回のg_hooks問題とは無関係の、別種の問題であるため、確実に
/// 動作を確認できている malloc/free のみをこの特別扱いの対象とする。
private template isCoreAllocatorFunc(alias func)
{
	import std.traits : moduleName;
	static if (__traits(compiles, moduleName!func))
	{
		private enum id = __traits(identifier, func);
		enum bool isCoreAllocatorFunc = moduleName!func == "core.stdc.stdlib" &&
			(id == "malloc" || id == "free");
	}
	else
	{
		enum bool isCoreAllocatorFunc = false;
	}
}

private enum MAX_ALLOCATOR_HOOKS = 4; // malloc/free程度なので少数で十分

private struct HookSlot
{
	string key;
	HookData data;
	bool used;
}

private __gshared HookSlot[MAX_ALLOCATOR_HOOKS] g_allocatorHookSlots;
private __gshared size_t g_allocatorHookSlotCount = 0;

/// funcに対応するHookDataへのポインタを返す。無ければnull。
/// (isCoreAllocatorFuncか否かで参照先を自動的に切り替える)
private HookData* findHook(alias func)() @trusted
{
	static if (isCoreAllocatorFunc!func)
	{
		foreach (i; 0 .. g_allocatorHookSlotCount)
		{
			if (g_allocatorHookSlots[i].used && g_allocatorHookSlots[i].key == func.mangleof)
				return &g_allocatorHookSlots[i].data;
		}
		return null;
	}
	else
	{
		return func.mangleof in g_hooks;
	}
}

/// 新規エントリを追加してそのポインタを返す。
/// (アロケータ専用スロットが尽きた場合のみnullを返しうる)
private HookData* insertHook(alias func)() @trusted
{
	static if (isCoreAllocatorFunc!func)
	{
		if (g_allocatorHookSlotCount >= MAX_ALLOCATOR_HOOKS)
			return null;
		auto idx = g_allocatorHookSlotCount++;
		g_allocatorHookSlots[idx] = HookSlot.init;
		g_allocatorHookSlots[idx].key = func.mangleof;
		g_allocatorHookSlots[idx].used = true;
		return &g_allocatorHookSlots[idx].data;
	}
	else
	{
		g_hooks[func.mangleof] = HookData.init;
		return func.mangleof in g_hooks;
	}
}

/// エントリを削除する
private void removeHook(alias func)() @trusted
{
	static if (isCoreAllocatorFunc!func)
	{
		foreach (i; 0 .. g_allocatorHookSlotCount)
		{
			if (g_allocatorHookSlots[i].used && g_allocatorHookSlots[i].key == func.mangleof)
			{
				g_allocatorHookSlots[i].used = false;
				return;
			}
		}
	}
	else
	{
		g_hooks.remove(func.mangleof);
	}
}

/*******************************************************************************
 * 上記フック情報レジストリを保護するスピンロック。
 * 詳細は FIX_NOTES.md / ISSUE_free_access_violation.md を参照。
 */
private shared int g_hooksLock = 0;

private void lockHooks() nothrow @nogc
{
	import core.atomic;
	while (!cas(&g_hooksLock, 0, 1))
	{
	}
}

private void unlockHooks() nothrow @nogc
{
	import core.atomic;
	atomicStore(g_hooksLock, 0);
}

private ReturnType!func _generalHookImpl(alias func)(Parameters!func args)
if (!isMethod!func)
{
	alias DgType = ReturnType!func delegate(Parameters!func);
	lockHooks();
	auto hook = findHook!func();
	if (hook is null)
	{
		unlockHooks();
		assert(hook);
	}
	hook._counter++;
	bool hasCallback = hook._callback !is null;
	DgType callback;
	void* trampoline;
	if (hasCallback)
		callback = *cast(DgType*)(&hook._callback);
	else
		trampoline = hook._trampoline;
	unlockHooks();

	if (hasCallback)
		return callback(args);
	// NOTE: ここは trampoline 経由で元の関数(funcそのもの、あるいは
	// funcの続き)を呼び出す箇所。`ReturnType!func function(Parameters!func)`
	// という素朴な関数ポインタ型は常にD言語のデフォルトの呼び出し規約
	// (extern(D))になってしまい、funcが`extern(C)`(malloc/freeなどの
	// Cライブラリ関数)の場合、実際の呼び出し規約と食い違ってしまう。
	// x86_64ではDとCの呼び出し規約がたまたま一致するため問題が
	// 表面化しないが、32bit x86ではDのextern(D)とCのcdeclで引数の
	// 扱いが異なり、引数が正しく渡らずクラッシュする原因になっていた。
	// `typeof(&func)` を使うことで、funcが実際に宣言されている
	// リンケージ(extern(C)ならextern(C))をそのまま引き継ぐ。
	return (cast(typeof(&func))trampoline)(args);
}

/*******************************************************************************
 * `_generalHookImpl!func` を、funcと同じ呼び出し規約(リンケージ)で
 * 呼び出せるようにラップしたエントリポイント。
 *
 * `func`(例えば`extern(C)`の`malloc`/`free`)をフックする際、パッチ後の
 * `func`はこの関数のアドレスへ直接ジャンプするよう書き換えられる。
 * つまり、この関数自身が「funcであるかのように」呼び出される。
 * `_generalHookImpl`をそのまま使うと、それは常にD言語のデフォルトの
 * 呼び出し規約(extern(D))で宣言された関数になってしまい、
 * funcの実際の呼び出し規約(例えばCの`cdecl`)と食い違う。
 * x86_64ではDとCの呼び出し規約がたまたま一致するため問題が
 * 表面化しないが、32bit x86ではこの食い違いにより引数が正しく
 * 読み取れず、渡されるはずのポインタが全く別の値になってしまう
 * (結果としてクラッシュする)。
 *
 * ここでは `func` の実際のリンケージ(`std.traits.functionLinkage`)に
 * 合わせて `extern(...)` を切り替えたラッパー関数を用意することで、
 * 呼び出し規約を一致させる。`extern(C)`/`extern(Windows)`/`extern(C++)`
 * のようにDの既定と異なるリンケージの場合は、テンプレートインスタンス
 * ごとに一意なシンボル名を`pragma(mangle)`で明示的に指定し、
 * (Cリンケージはテンプレート引数によるマングリングが行われないため)
 * 複数の関数を同時にフックした際にシンボル名が衝突しないようにしている。
 */
private template _generalHookEntry(alias func)
if (!isMethod!func)
{
	import std.traits : functionLinkage;
	private enum _dinst_ghLinkage = functionLinkage!func;
	private enum _dinst_ghMangledName = "_dinst_gh_" ~ func.mangleof;

	static if (_dinst_ghLinkage == "C")
	{
		pragma(mangle, _dinst_ghMangledName)
		extern(C) ReturnType!func _generalHookEntry(Parameters!func args)
		{
			return _generalHookImpl!func(args);
		}
	}
	else static if (_dinst_ghLinkage == "Windows")
	{
		pragma(mangle, _dinst_ghMangledName)
		extern(Windows) ReturnType!func _generalHookEntry(Parameters!func args)
		{
			return _generalHookImpl!func(args);
		}
	}
	else static if (_dinst_ghLinkage == "C++")
	{
		pragma(mangle, _dinst_ghMangledName)
		extern(C++) ReturnType!func _generalHookEntry(Parameters!func args)
		{
			return _generalHookImpl!func(args);
		}
	}
	else
	{
		// D(デフォルト)。テンプレートインスタンスごとに自動的に
		// 一意な名前が付くため pragma(mangle) は不要。
		ReturnType!func _generalHookEntry(Parameters!func args)
		{
			return _generalHookImpl!func(args);
		}
	}
}

version (LDC)
{
	private ReturnType!func _generalHook(alias func)(ParentRef!func parent, Parameters!func args)
	if (isMethod!func)
	{
		alias DgType = ReturnType!func delegate(ParentRef!func, Parameters!func);
		lockHooks();
		auto hook = findHook!func();
		if (hook is null)
		{
			unlockHooks();
			assert(hook);
		}
		hook._counter++;
		bool hasCallback = hook._callback !is null;
		DgType callback;
		void* trampoline;
		if (hasCallback)
			callback = *cast(DgType*)(&hook._callback);
		else
			trampoline = hook._trampoline;
		unlockHooks();

		if (hasCallback)
			return callback(parent, args);
		return (cast(ReturnType!func function(ParentRef!func, Parameters!func))trampoline)(parent, args);
	}
}
else
{
	private ReturnType!func _generalHook(alias func)(Parameters!func args, ParentRef!func parent)
	if (isMethod!func)
	{
		alias DgType = ReturnType!func delegate(Parameters!func, ParentRef!func);
		lockHooks();
		auto hook = findHook!func();
		if (hook is null)
		{
			unlockHooks();
			assert(hook);
		}
		hook._counter++;
		bool hasCallback = hook._callback !is null;
		DgType callback;
		void* trampoline;
		if (hasCallback)
			callback = *cast(DgType*)(&hook._callback);
		else
			trampoline = hook._trampoline;
		unlockHooks();

		if (hasCallback)
			return callback(args, parent);
		return (cast(ReturnType!func function(Parameters!func, ParentRef!func))trampoline)(args, parent);
	}
}

// メソッド(クラス/構造体のメンバ関数)は常にD言語のABIで呼び出されるため、
// extern(C)等のリンケージ食い違いの問題は起こらない。createHook()から
// 統一的に `_generalHookEntry!func` の形で参照できるよう、既存の
// `_generalHook!func`(メソッド版)へそのままエイリアスする。
private template _generalHookEntry(alias func)
if (isMethod!func)
{
	alias _generalHookEntry = _generalHook!func;
}

/*******************************************************************************
 * 
 */
bool createHook(alias func)()
{
	lockHooks();
	bool already = (findHook!func()) !is null;
	HookData* hook;
	if (already)
		hook = findHook!func();
	else
		// _generalHook!func はこのフック情報を参照する。
		// そのため、実際にバイナリへパッチを当てる「前」に登録を
		// 完了させておく必要がある。
		//
		// (以前は「パッチを当ててから登録する」という順序だったため、
		//  パッチ直後・登録前の一瞬の間に何らかの経路(druntime自身の内部処理など)
		//  で func が呼び出されると、_generalHook!func 内の `assert(hook)` が
		//  失敗していた。よりによって free() のようにランタイム自身が内部で
		//  依存している関数をフックした場合にこれが起こりやすく、
		//  パッチしたばかりの重要な関数の呼び出し中に異常終了するため、
		//  Windowsではアクセス違反として観測されることがある)
		hook = insertHook!func();
	unlockHooks();

	if (already)
		return true;
	if (hook is null)
		return false; // MAX_HOOKS に達した

	// NOTE: hook._create() はここではロックを保持しない状態で呼び出す。
	// _create() の内部(determineStolenBytesが使うcapstoneの内部処理など)が
	// 別の、既にフック済みの関数を間接的に呼び出す可能性があり、
	// その場合 _generalHook 側でも同じロックを取得しようとするため、
	// ここでロックを保持したままだと自己デッドロックしてしまう。
	if (!hook._create(&func, &(_generalHookEntry!func)))
	{
		lockHooks();
		removeHook!func();
		unlockHooks();
		return false;
	}
	return true;
}

/*******************************************************************************
 * 
 */
void setHookFunc(alias func)(ReturnType!func delegate(Parameters!func) dg) @trusted
if (!isMethod!func)
{
	auto hook = findHook!func();
	assert(hook);
	alias DgType = void delegate();
	synchronized (hook._mutex)
		hook._callback = *cast(DgType*)cast(void*)&dg;
}
/// ditto
void setHookFunc(alias func)(ReturnType!func delegate(ParentRef!func, Parameters!func) dg) @trusted
if (isMethod!func)
{
	auto hook = findHook!func();
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
void setHookFunc(alias func)(ReturnType!func function(Parameters!func) dg) @trusted
if (!isMethod!func)
{
	import std.functional;
	setHookFunc!func(toDelegate(dg));
}
/// ditto
void setHookFunc(alias func)(ReturnType!func function(ParentRef!func, Parameters!func) dg) @trusted
if (isMethod!func)
{
	import std.functional;
	setHookFunc!func(toDelegate(dg));
}

/*******************************************************************************
 * 
 */
void clearHookState(alias func)() @trusted
{
	auto hook = findHook!func();
	assert(hook);
	synchronized (hook._mutex)
		hook._clearState();
}

/*******************************************************************************
 * 
 */
ReturnType!func callHookOriginal(alias func)(Parameters!func args) @trusted
{
	auto hook = findHook!func();
	assert(hook);
	// NOTE: _generalHookImpl 内のトランポリン呼び出しと同じ理由により、
	// `ReturnType!func function(Parameters!func)` という素朴な関数
	// ポインタ型(常にD言語のデフォルトのリンケージになる)ではなく
	// `typeof(&func)` を使い、funcの実際のリンケージ(extern(C)なら
	// extern(C))をそのまま引き継ぐ。x86_64ではDとCの呼び出し規約が
	// たまたま一致するため問題が表面化しないが、32bit x86では
	// これを怠ると引数が正しく渡らず、ヒープ破壊(不正なポインタでの
	// free()呼び出し等)を引き起こす。
	typeof(&func) fn;
	synchronized (hook._mutex)
		fn = cast(typeof(&func))hook._trampoline;
	return fn(args);
}



/*******************************************************************************
 * 
 */
struct SetupHook(alias func)
{
private:
	import core.sync.mutex;
	import dinst.arch;
	import core.demangle;
	Mutex _mutex;
	void lockMutex() @trusted
	{
		if (_mutex)
			return;
		auto hook = findHook!func();
		assert(hook);
		_mutex = hook._mutex;
		_mutex.lock();
	}
public:
	shared static this() @trusted
	{
		cast()createHook!func();
	}
	///
	bool opCast(T: bool)() const
	{
		return cast(bool)(findHook!func());
	}
	///
	~this() @trusted
	{
		if (findHook!func())
		{
			clearHookState!func();
			if (_mutex)
				_mutex.unlock();
		}
	}
	///
	ReturnType!func callOrig(Parameters!func args) @safe
	{
		return callHookOriginal!func(args);
	}
	
	///
	void hook()(ReturnType!func function(Parameters!func) fn) @safe
	if (!isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(fn);
	}
	/// ditto
	void hook()(ReturnType!func function(ParentRef!func, Parameters!func) fn) @safe
	if (isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(fn);
	}
	/// ditto
	void hook()(ReturnType!func delegate(Parameters!func) dg) @safe
	if (!isMethod!func)
	{
		lockMutex();
		return setHookFunc!func(dg);
	}
	/// ditto
	void hook()(ReturnType!func delegate(ParentRef!func, Parameters!func) dg) @safe
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

bool setupHooks(funcs...)() @trusted
{
	if (!isSupported)
		return false;
	bool ret = true;
	static foreach (alias f; funcs)
	{{
		ret &= cast(bool)setupHook!f;
		assert(ret, "Failed to setup: " ~ fullyQualifiedName!f);
	}}
	return true;
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
	if (!setupHooks!foo)
		return;
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
	if (!setupHooks!(C.foo))
		return;
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
