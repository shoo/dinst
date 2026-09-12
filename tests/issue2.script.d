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
	if (!isSupported)
		return;
	auto hook = setupHook!free;
	static int pass;
	hook.hook(delegate (void* ptr) {
		pass = 1;
		hook.callOrig(ptr);
	});
	auto ptr = malloc(100);
	free(ptr);
	assert(pass == 1);
}
