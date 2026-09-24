/+ dub.sdl:
name "issue2"
dependency "dinst" path=".."
+/
module tests.issue2;

import std.stdio;
import core.stdc.stdlib : malloc, free;
import dinst;

void main()
{
import core.stdc.stdio; setbuf(cast(FILE*)core.stdc.stdio.stdout, null);
	if (!isSupported)
		return;
writeln("TEST 1");
	auto hook = setupHook!free;
writeln("TEST 2");
	static int pass;
	hook.hook(delegate (void* ptr) {
writeln("TEST 5");
		pass = 1;
		hook.callOrig(ptr);
writeln("TEST 6");
	});
writeln("TEST 3");
	auto ptr = malloc(100);
writeln("TEST 4");
	free(ptr);
writeln("TEST 7");
	assert(pass == 1);
writeln("TEST 8");
}
