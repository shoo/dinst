# dinst
[![GitHub tag](https://img.shields.io/github/tag/shoo/dinst.svg?maxAge=86400)](#)
[![CI Status](https://github.com/shoo/dinst/actions/workflows/main.yml/badge.svg)](https://github.com/shoo/dinst/actions/workflows/main.yml)
[![downloads](https://img.shields.io/dub/dt/dinst.svg?cacheSeconds=3600)](https://code.dlang.org/packages/dinst)
[![BSL-1.0](http://img.shields.io/badge/license-BSL--1.0-blue.svg?style=flat)](./LICENSE)
[![codecov](https://codecov.io/gh/shoo/dinst/branch/main/graph/badge.svg)](https://codecov.io/gh/shoo/dinst)
[![Document](http://img.shields.io/badge/API_Document-purple.svg?style=flat)](https://shoo.github.io/dinst)

Dynamic instrumentation for D unittests.

Dynamic instrumentation is a technique that combines runtime patching and trampolines to rewrite the contents of a function.
dinst was primarily created for unit testing purposes.

In unit testing, it is often desirable to rewrite the behavior of functions called by the test subject.
For example:
- Testing the case where `malloc()` returns `null`
- Testing the case where network communication fails
- Testing the case where hardware fails

Some of these cases can be very difficult to reproduce from the outside. For example, what kind of setup would be necessary beforehand to make `malloc()` for 64 bytes fail?
In a normal execution environment, `malloc()` returns `null` "when the heap is exhausted," but truly exhausting memory in a unit test is not appropriate due to low reproducibility and its impact on other tests.

In D, you can inject dependencies from the outside using templates.
But would you? Template code that you wouldn't use for its intended purpose just for testing?

This is where the library comes in handy.
Here is an example of how to use it:

**foo.d**:
```d
int foo(int a) @safe
{
	return a * a;
}
```

**bar.d**:
```d
int bar(int a) @safe
{
	return foo(a) + a;
}
```

Let's consider testing `bar()`, assuming we cannot touch the implementation of `foo()`. However, if our goal is to test whether `bar()` is implemented correctly according to `foo()`'s behavior, we might want to stub (rewrite the function's body to perform a simple response) or mock (replace the function with a dummy that behaves appropriately) `foo()`. This is where this library comes in.

```d
@safe unittest
{
	import dinst;
	auto foo = setupHook!foo();
	assert(bar(1) == 2);
	foo.hook(a => 10);
	assert(bar(1) == 11);
}
```

By writing unit test code like the example above, you can dynamically rewrite the behavior of `foo`.

# Install
This library uses a machine code parsing library called capstone.
You need to install [cmake](https://cmake.org/) before execution because it performs a build before runtime.
*Note: For Windows, pre-built binaries are included, so it is not strictly necessary, but cmake is required if you intend to rebuild.*

dub command:
```sh
dub add dinst
```

If you are only using it for unit tests, do the following.
Please be careful not to use it outside of the unittest blocks.

**dub.json**:
```json
{
  "configurations": [
    {
      "name": "unittest",
      "dependencies": { "dinst": "~>0.0.1" }
    }
  ]
}
```

# Usage

Prepare to hook a function by calling `setupHook!func`.
Calling this function performs dynamic instrumentation at program startup, allowing you to hook at any time.
Storing the state in a variable, like `auto hookFunc = setupHook!func();`, will clear the hook function when the lifetime of the variable ends.

You hook by calling a method on the variable saved above.
You can specify a lambda like `hookFunc.hook(a => true)`, or you can specify a function pointer of a free function or a closure like `hookFunc.hook(&myFunc)`.

The behavior of free functions can be rewritten as follows.

```d
@safe unittest
{
	import dinst;
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
```

It is also possible to rewrite class member functions.
The hook function for class member functions takes the class as its first argument.

```d
@safe unittest
{
	import dinst;
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
```


# License
This library itself is under the [BSL-1.0](LICENSE) license.
However, programs that this library depends on have separate licenses.
- capstone [BSD-3 clause](https://github.com/capstone-engine/capstone/tree/5.0.6/LICENSES)

Additionally, this project includes some pre-built binaries.
[Licenses are here](./licenses)

If you depend on this library, please be aware that you will also be depending on the aforementioned libraries.
We recommend listing dependencies only in the unittest configuration (a special configuration used for unit tests via dub test) to avoid including dependencies in your product code.

```json
{
  "configurations": [
    {
      "name": "unittest",
      "dependencies": { "dinst": "~>0.0.1" }
    }
  ]
}
```
