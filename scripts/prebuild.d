module scripts.prebuild;

enum tmpDir = "lib/.tmp";

version (X86)
{
	enum isX86_64 = false;
	enum isX86 = true;
	enum isAArch64 = false;
}
else version (X86_64)
{
	enum isX86_64 = true;
	enum isX86 = false;
	enum isAArch64 = false;
}
else version (AArch64)
{
	enum isX86_64 = false;
	enum isX86 = false;
	enum isAArch64 = true;
}
version (Windows)
{
	enum isWindows = true;
	enum isPosix = false;
	enum isLinux = false;
	enum isMacos = false;
}
else version (Posix)
{
	enum isWindows = false;
	enum isPosix = true;
	version (linux)
	{
		enum isLinux = true;
		enum isMacos = false;
	}
	else version (OSX)
	{
		enum isLinux = false;
		enum isMacos = true;
	}
	else static assert(0);
}
else static assert(0);


static if (isWindows)
{
	enum capstoneSrcUrl = "https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.zip";
	enum capstoneSrcDir = "capstone-5.0.6";
}
static if (isPosix)
{
	enum capstoneSrcUrl = "https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.zip";
	enum capstoneSrcDir = "capstone-5.0.6";
}

static if (isWindows && isX86)
	enum targetLibDir = "lib/windows-x86";
else static if (isWindows && isX86_64)
	enum targetLibDir = "lib/windows-x86_64";
else static if (isWindows && isAArch64)
	enum targetLibDir = "lib/windows-aarch64";
else static if (isLinux && isX86)
	enum targetLibDir = "lib/linux-x86";
else static if (isLinux && isX86_64)
	enum targetLibDir = "lib/linux-x86_64";
else static if (isLinux && isAArch64)
	enum targetLibDir = "lib/linux-aarch64";
else static if (isMacos && isX86_64)
	enum targetLibDir = "lib/macos-x86_64";
else static if (isMacos && isAArch64)
	enum targetLibDir = "lib/macos-aarch64";
else static assert(0);

static if (isWindows)
	enum targetLibName = "capstone.lib";
else static if (isPosix)
	enum targetLibName = "libcapstone.a";
else static assert(0);

void download(string url, string file)
{
	try
	{
		import std.net.curl;
		std.net.curl.download(url, file);
	}
	catch (Exception e)
	{
		import std; writeln(e.msg);
		import std.process;
		spawnProcess(["curl", "-L", "-o", file, url]).wait();
	}
}

void downloadSrc()
{
	import std.file, std.path, std.zip, std.string;
	download(capstoneSrcUrl, tmpDir.buildPath("capstone.zip"));
	auto zipData = std.file.read(tmpDir.buildPath("capstone.zip"));
	auto archive = new ZipArchive(zipData);
	foreach (path, de; archive.directory)
	{
		auto filePath = tmpDir.buildPath(path);
		if (filePath.endsWith("/"))
			continue;
		mkdirRecurse(filePath.dirName);
		auto expanded = archive.expand(de);
		std.file.write(filePath, expanded);
	}
}


void build()
{
	import std.process, std.path, std.file, std.string, std.stdio;
	static if (isWindows)
	{
		string[] args;
		string[string] env;
		string[] buildArgs;
		string builtLib;
		auto vswhere = environment.get("ProgramFiles(x86)").buildPath("Microsoft Visual Studio", "Installer", "vswhere.exe");
		if (vswhere.exists)
		{
			//static if (isX86)
			//	enum varsEnv = "x86";
			//else static if (isX86_64)
			//	enum varsEnv = "x64";
			//else static if (isAArch64)
			//	enum varsEnv = "amd64_arm64";
			//else static assert(0);
			//auto vsInstallPath = execute([vswhere, "-latest", "-products", "*",
			//	"-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
			//	"-property", "installationPath"]).output.chomp();
			//auto vcvarsallPath = vsInstallPath.buildPath("VC", "Auxiliary", "Build", "vcvarsall.bat");
			//if (vcvarsallPath.exists)
			//{
			//	auto varsall = executeShell("call \"" ~ vcvarsallPath ~ "\" " ~ varsEnv
			//		~ " && echo xxxxxxxxxxx delim xxxxxxxxxxxxxx"
			//		~ " && set").output;
			//	foreach (line; varsall.split("xxxxxxxxxxx delim xxxxxxxxxxxxxx")[1].splitLines)
			//	{
			//		auto pair = line.split("=");
			//		if (pair.length == 2)
			//			env[pair[0]] = pair[1];
			//	}
			//}
			//args = ["cmake", "-G", "Ninja", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir)];
			static if (isX86)
				enum arch = "Win32";
			else static if (isX86_64)
				enum arch = "x64";
			else static if (isAArch64)
				enum arch = "ARM64";
			args = ["cmake", "-A", arch, "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
				"-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off",
				"-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"];
			buildArgs = ["--config", "Release"];
			builtLib = "Release".buildPath(targetLibName);
		}
		if (args.length == 0)
		{
			static if (isX86)
				args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
					"-DCMAKE_C_FLAGS=-m32", "-DCMAKE_CXX_FLAGS=-m32",
					"-DCMAKE_EXE_LINKER_FLAGS=-m32", "-DCMAKE_SHARED_LINKER_FLAGS=-m32",
					"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
			else static if (isX86_64)
				args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
					"-DCMAKE_C_FLAGS=-m64", "-DCMAKE_CXX_FLAGS=-m64",
					"-DCMAKE_EXE_LINKER_FLAGS=-m64", "-DCMAKE_SHARED_LINKER_FLAGS=-m64",
					"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
			else static if (isAArch64)
				args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
					"-DCMAKE_C_FLAGS=-target aarch64-pc-windows-gnu",
					"-DCMAKE_CXX_FLAGS=-target aarch64-pc-windows-gnu",
					"-DCMAKE_EXE_LINKER_FLAGS=-target aarch64-pc-windows-gnu",
					"-DCMAKE_SHARED_LINKER_FLAGS=-target aarch64-pc-windows-gnu",
					"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
			else static assert(0);
			builtLib = targetLibName;
		}
	}
	else
	{
		string[] args;
		string[string] env;
		string[] buildArgs;
		string builtLib;
		static if (isX86)
			args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
				"-DCMAKE_C_FLAGS=-m32", "-DCMAKE_CXX_FLAGS=-m32",
				"-DCMAKE_EXE_LINKER_FLAGS=-m32", "-DCMAKE_SHARED_LINKER_FLAGS=-m32",
				"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
		else static if (isX86_64)
			args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
				"-DCMAKE_C_FLAGS=-m64", "-DCMAKE_CXX_FLAGS=-m64",
				"-DCMAKE_EXE_LINKER_FLAGS=-m64", "-DCMAKE_SHARED_LINKER_FLAGS=-m64",
				"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
		else static if (isLinux && isAArch64)
			args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
				"-DCMAKE_C_FLAGS=-target aarch64-linux-gnu",
				"-DCMAKE_CXX_FLAGS=-target aarch64-linux-gnu",
				"-DCMAKE_EXE_LINKER_FLAGS=-target aarch64-linux-gnu",
				"-DCMAKE_SHARED_LINKER_FLAGS=-target aarch64-linux-gnu",
				"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
		else static if (isMacos && isAArch64)
			args = ["cmake", "-B", tmpDir.buildPath("build"), tmpDir.buildPath(capstoneSrcDir),
				"-DCMAKE_C_FLAGS=-arch arm64", "-DCMAKE_CXX_FLAGS=-arch arm64",
				"-DCMAKE_EXE_LINKER_FLAGS=-arch arm64", "-DCMAKE_SHARED_LINKER_FLAGS=-arch arm64",
				"-DCMAKE_BUILD_TYPE=Release", "-DCAPSTONE_BUILD_TESTS=Off", "-DCAPSTONE_BUILD_CSTOOL=Off"];
		else static assert(0);
		builtLib = targetLibName;
	}
	
	auto pid = spawnProcess(args, env: env);
	wait(pid);
	pid = spawnProcess(["cmake", "--build", tmpDir.buildPath("build")] ~ buildArgs, env: env);
	wait(pid);
	if (targetLibDir.buildPath(targetLibName).exists)
		std.file.remove(targetLibDir.buildPath(targetLibName));
	mkdirRecurse(targetLibDir);
	copy(tmpDir.buildPath("build", builtLib), targetLibDir.buildPath(targetLibName));
}

void main(string[] args)
{
	import std.file, std.path;
	if (targetLibDir.buildPath(targetLibName).exists)
		return;
	mkdirRecurse(tmpDir);
	scope (exit)
		rmdirRecurse(tmpDir);
	downloadSrc();
	build();
}
