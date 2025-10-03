module dinst.arch;

version (X86)
{
	///
	enum bool isX86 = true;
	///
	enum bool isX86_64 = false;
	///
	enum bool isAArch64 = false;
}
else version (X86_64)
{
	///
	enum bool isX86 = false;
	///
	enum bool isX86_64 = true;
	///
	enum bool isAArch64 = false;
}
else version (AArch64)
{
	///
	enum bool isX86 = false;
	///
	enum bool isX86_64 = false;
	///
	enum bool isAArch64 = true;
}
else static assert(0, "Unsupported Architecture");

version (Windows)
{
	///
	enum bool isWindows = true;
	///
	enum bool isLinux = false;
	///
	enum bool isPosix = false;
	///
	enum bool isMacos = false;
}
else version (linux)
{
	///
	enum bool isWindows = false;
	///
	enum bool isLinux = true;
	///
	enum bool isPosix = true;
	///
	enum bool isMacos = false;
}
else version (OSX)
{
	///
	enum bool isWindows = false;
	///
	enum bool isLinux = false;
	///
	enum bool isPosix = true;
	///
	enum bool isMacos = true;
}
else static assert(0, "Unsupported OS");

///
enum bool isSupported = 0
	|| (isWindows && isX86)
	|| (isWindows && isX86_64)
	|| (isLinux && isX86)
	|| (isLinux && isX86_64);
