module src.bar;
import src.foo;

int bar(int a) @safe
{
	return foo(a) + a;
}


@safe unittest
{
	import dinst;
	auto foo = setupHook!foo();
	assert(bar(1) == 2);
	foo.hook(a => 10);
	assert(bar(1) == 11);
}
