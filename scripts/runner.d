module scripts.runner;

import std;

///
struct Defines
{
static:
	/// ドキュメントジェネレータを指定します。
	/// gendocのバージョンが更新されたら変更してください。
	immutable documentGenerator = "gendoc";
	
	/// テスト対象にするサブパッケージを指定します。
	/// サブパッケージが追加されたらここにも追加してください。
	immutable string integrationTestCaseDir = "tests";
	
	/// テスト対象にするサブパッケージを指定します。
	/// サブパッケージが追加されたらここにも追加してください。
	immutable string[] subPkgs = [];
}

///
struct Config
{
	///
	string os;
	///
	string arch;
	///
	string compiler;
	///
	string hostArch;
	///
	string targetArch;
	///
	string hostCompiler;
	///
	string targetCompiler;
	///
	string archiveSuffix;
	///
	string scriptDir = __FILE__.dirName();
	///
	string projectName;
	///
	string refName;
	///
	string[] integrationTestTargets;
}
///
__gshared Config config;

///
int main(string[] args)
{
	string mode;
	import core.stdc.stdio;
	setvbuf(stdout, null, _IONBF, 0);
	
	version (Windows)      {config.os = "windows";}
	else version (linux)   {config.os = "linux";}
	else version (OSX)     {config.os = "osx";}
	else static assert(0, "Unsupported OS");
	
	version (Windows)      {config.archiveSuffix = ".zip";}
	else version (linux)   {config.archiveSuffix = ".tar.gz";}
	else version (OSX)     {config.archiveSuffix = ".tar.gz";}
	else static assert(0, "Unsupported OS");
	
	version (D_LP64)      {config.arch = "x86_64";}
	else                  {config.arch = "x86";}
	
	version (DigitalMars) {config.compiler = "dmd";}
	else version (LDC)    {config.compiler = "ldc2";}
	else version (GNU)    {config.compiler = "gdc";}
	else static assert(0, "Unsupported Compiler");
	
	config.projectName = environment.get("GITHUB_REPOSITORY").chompPrefix(environment.get("GITHUB_ACTOR") ~ "/");
	config.refName = getRefName();
	
	config.hostArch       = config.arch;
	config.targetArch     = config.arch;
	config.hostCompiler   = config.compiler;
	config.targetCompiler = config.compiler;
	
	string tmpHostArch, tmpTargetArch, tmpHostCompiler, tmpTargetCompiler;
	string[] exDubOpts;
	
	args.getopt(
		"a|arch",                     &config.arch,
		"os",                         &config.os,
		"host-arch",                  &tmpHostArch,
		"target-arch",                &tmpTargetArch,
		"c|compiler",                 &config.compiler,
		"host-compiler",              &tmpHostCompiler,
		"target-compiler",            &tmpTargetCompiler,
		"archive-suffix",             &config.archiveSuffix,
		"m|mode",                     &mode,
		"t|integration-test-targets", &config.integrationTestTargets,
		"exdubopts",                  &exDubOpts);
	
	config.hostArch = tmpHostArch ? tmpHostArch : config.arch;
	config.targetArch = tmpTargetArch ? tmpTargetArch : config.arch;
	config.hostCompiler = tmpHostCompiler ? tmpHostCompiler : config.compiler;
	config.targetCompiler = tmpTargetCompiler ? tmpTargetCompiler : config.compiler;
	
	switch (mode.toLower)
	{
	case "unit-test":
	case "unittest":
	case "ut":
		unitTest(exDubOpts);
		break;
	case "integration-test":
	case "integrationtest":
	case "it":
	case "tt":
		integrationTest(exDubOpts);
		break;
	case "test":
		unitTest(exDubOpts);
		integrationTest(exDubOpts);
		break;
	case "create-release-build":
	case "createreleasebuild":
	case "release-build":
	case "releasebuild":
	case "build":
		createReleaseBuild(exDubOpts);
		break;
	case "create-archive":
	case "createarchive":
		createArchive();
		break;
	case "create-document":
	case "createdocument":
	case "create-document-test":
	case "createdocumenttest":
	case "generate-document":
	case "generatedocument":
	case "generate-document-test":
	case "generatedocumenttest":
	case "gendoc":
	case "docs":
	case "doc":
		generateDocument();
		break;
	case "all":
		unitTest(exDubOpts);
		integrationTest(exDubOpts);
		createReleaseBuild(exDubOpts);
		generateDocument();
		createArchive();
		break;
	default:
		enforce(0, "Unknown mode: " ~ mode);
		break;
	}
	return 0;
}

///
void unitTest(string[] exDubOpts = null)
{
	string[string] env;
	auto covdir = config.scriptDir.buildNormalizedPath("../.cov");
	if (!covdir.exists)
		mkdirRecurse(covdir);
	auto covopt = [
		"--DRT-covopt=dstpath:" ~ covdir.absolutePath(),
		"--DRT-covopt=merge:1"];
	env.addCurlPath();
	writeln("#######################################");
	writeln("## Unit Test                         ##");
	writeln("#######################################");
	exec(["dub",
		"test",
		"-a", config.hostArch,
		"--coverage",
		"--compiler", config.hostCompiler]
		~ exDubOpts ~ ["--"] ~ covopt,
		null, env);
	foreach (pkgName; Defines.subPkgs)
	{
		exec(["dub",
			"test",
			":" ~ pkgName,
			"-a", config.hostArch,
			"--coverage",
			"--compiler", config.hostCompiler]
			~ exDubOpts ~ ["--"] ~ covopt,
			null, env);
	}
}

///
void generateDocument()
{
	string[string] env;
	env.addCurlPath();
	exec(["dub", "run", Defines.documentGenerator, "-y",
		"--",
		"-a=x86_64", "-b=release"], null, env);
}

///
void createReleaseBuild(string[] exDubOpts = null)
{
	exec(["dub",
		"build",
		"-a",              config.hostArch,
		"-b=release",
		"--compiler",      config.hostCompiler] ~ exDubOpts);
	foreach (subpkg; Defines.subPkgs)
		exec(["dub",
			"build",
			":" ~ subpkg,
			"-a",              config.hostArch,
			"-b=release",
			"--compiler",      config.hostCompiler] ~ exDubOpts);
}


///
void integrationTest(string[] exDubOpts = null)
{
	string[string] env;
	env.addCurlPath();
	auto projDir = config.scriptDir.absolutePath().buildNormalizedPath("..");
	auto covDir  = projDir.buildPath(".cov").absolutePath();
	if (!covDir.exists)
		mkdirRecurse(covDir);
	
	auto covopt = [
		"--DRT-covopt=dstpath:" ~ covDir,
		"--DRT-covopt=srcpath:" ~ projDir,
		"--DRT-covopt=merge:1"];
	
	bool dirTest(string entry)
	{
		auto testDir = entry.absolutePath().buildNormalizedPath();
		auto expMap = [
			"project_root": projDir,
			"test_dir": testDir,
		];
		auto getOpts(string defaultname, string optfile, string ignorefile)
		{
			struct Opt
			{
				string name;
				string buildWorkDir;
				string[] dubArgs;
				string runWorkDir;
				string[] args;
				string[string] env;
			}
			if (entry.buildPath(ignorefile).exists)
				return Opt[].init;
			if (!entry.buildPath(optfile).exists)
				return [Opt("default", projDir, [], testDir, [], env)];
			Opt[] ret;
			import std.file: read;
			auto jvRoot = parseJSON(cast(string)read(entry.buildPath(optfile)));
			foreach (i, jvOpt; jvRoot.array)
			{
				auto dat = Opt(text(defaultname, i), projDir, [], testDir, [], env);
				if (auto str = jvOpt.getStr("name", expMap))
					dat.name = str;
				if (auto str = jvOpt.getStr("buildWorkDir", expMap))
					dat.buildWorkDir = str;
				dat.dubArgs = jvOpt.getAry("dubArgs", expMap);
				if (auto str = jvOpt.getStr("runWorkDir", expMap))
					dat.runWorkDir = str;
				dat.args = jvOpt.getAry("args", expMap);
				foreach (k, v; jvOpt.getObj("env", expMap))
					dat.env[k] = v;
				ret ~= dat;
			}
			return ret;
		}
		if (entry.isDir)
		{
			auto buildOpts   = getOpts("build", ".build_opts", ".no_build");
			auto testOpts    = getOpts("test", ".test_opts", ".no_test");
			auto runOpts     = getOpts("run", ".run_opts", ".no_run");
			auto no_coverage = entry.buildPath(".no_coverage").exists;
			auto dubCommonArgs = [
				"-a",         config.targetArch,
				"--compiler", config.targetCompiler] ~ exDubOpts;
			foreach (buildOpt; buildOpts)
			{
				dispLog("INFO", entry.baseName, "build test for " ~ buildOpt.name);
				auto dubArgs = (buildOpt.dubArgs.length > 0 ? dubCommonArgs ~ buildOpt.dubArgs : dubCommonArgs);
				dubArgs ~= "--root=" ~ testDir;
				exec(["dub", "build", "-b=release"] ~ dubArgs, buildOpt.buildWorkDir, buildOpt.env);
			}
			foreach (testOpt; testOpts)
			{
				dispLog("INFO", entry.baseName, "unittest for " ~ testOpt.name);
				auto dubArgs = (testOpt.dubArgs.length > 0 ? dubCommonArgs ~ testOpt.dubArgs : dubCommonArgs)
				             ~ (!no_coverage ? ["-b=unittest-cov", "-c=unittest"] : ["-b=unittest", "-c=unittest"]);
				auto desc = cmd(["dub", "describe", "--verror"] ~ dubArgs, ".", testOpt.env).parseJSON();
				auto targetExe = buildNormalizedPath(
					desc["packages"][0]["path"].str,
					desc["packages"][0]["targetPath"].str,
					desc["packages"][0]["targetFileName"].str);
				dubArgs ~= "--root=" ~ testDir;
				exec(["dub", "build"] ~ dubArgs, testOpt.buildWorkDir, testOpt.env);
				auto exeArgs = (!no_coverage ? covopt : null);
				exec([targetExe] ~ exeArgs, testOpt.runWorkDir, testOpt.env);
			}
			foreach (runOpt; runOpts)
			{
				dispLog("INFO", entry.baseName, "run test for " ~ runOpt.name);
				auto dubArgs = (runOpt.dubArgs.length > 0 ? dubCommonArgs ~ runOpt.dubArgs : dubCommonArgs)
				             ~ (!no_coverage ? ["-b=cov"] : ["-b=debug"]);
				dubArgs ~= "--root=" ~ testDir;
				auto desc = cmd(["dub", "describe", "--verror"] ~ dubArgs, ".", runOpt.env).parseJSON();
				auto targetExe = buildNormalizedPath(
					desc["packages"][0]["path"].str,
					desc["packages"][0]["targetPath"].str,
					desc["packages"][0]["targetFileName"].str);
				exec(["dub", "build", "-v", "-f"] ~ dubArgs, runOpt.buildWorkDir, runOpt.env);
				auto exeArgs = runOpt.args ~ (!no_coverage ? covopt : null);
				exec([targetExe] ~ exeArgs, runOpt.runWorkDir, runOpt.env);
			}
			return !(buildOpts.length == 0 && testOpts.length == 0 && runOpts.length == 0);
		}
		else switch (entry.extension)
		{
		case ".d":
			// rdmd
			dispLog("INFO", entry.baseName, "rdmd script test");
			auto dmdMachineTarget = config.arch == "x86" ? "-m32" : "-m64";
			exec(["rdmd", dmdMachineTarget, entry.baseName], entry.dirName, env);
			return true;
			break;
		case ".sh":
			// $SHELLまたはbashがあれば
			if (auto sh = environment.get("SHELL"))
			{
				dispLog("INFO", entry.baseName, "shell script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			if (auto sh = searchPath("bash"))
			{
				dispLog("INFO", entry.baseName, "bash shell script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			break;
		case ".bat":
			// %COMSPEC%があれば
			if (auto sh = environment.get("COMSPEC"))
			{
				dispLog("INFO", entry.baseName, "commandline batch test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			break;
		case ".ps1":
			// pwsh || powershellがあれば
			if (auto sh = searchPath("pwsh"))
			{
				dispLog("INFO", entry.baseName, "powershell script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			else if (auto sh = searchPath("powershell"))
			{
				dispLog("INFO", entry.baseName, "powershell script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			break;
		case ".py":
			// python || python3があれば
			if (auto sh = searchPath("python"))
			{
				dispLog("INFO", entry.baseName, "python script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			else if (auto sh = searchPath("python3"))
			{
				dispLog("INFO", entry.baseName, "python3 script test");
				exec([sh, entry], entry.dirName, env);
				return true;
			}
			break;
		default:
			// なにもしない
		}
		return false;
	}
	bool subPkgTest(string pkgName, string confName)
	{
		auto dubCommonArgs = [
			"-a",         config.targetArch,
			"--compiler", config.targetCompiler,
			"-b",         "cov"] ~ exDubOpts;
		string descStr;
		try
		{
			descStr = cmd(["dub", "describe", ":" ~ pkgName, "-c", confName, "--verror"] ~ dubCommonArgs, null, env);
			dubCommonArgs ~= ["-c", confName];
		}
		catch (Exception)
		{
			descStr = cmd(["dub", "describe", ":" ~ pkgName, "--verror"] ~ dubCommonArgs, null, env);
		}
		auto desc = descStr.parseJSON();
		if (desc["packages"][0]["targetType"].str != "executable")
			return false;
		auto targetExe = buildNormalizedPath(
			desc["packages"][0]["path"].str,
			desc["packages"][0]["targetPath"].str,
			desc["packages"][0]["targetFileName"].str);
		exec(["dub", "build", ":" ~ pkgName] ~ dubCommonArgs, null, env);
		exec([targetExe], null, env);
		return true;
	}
	
	struct Result
	{
		string name;
		bool executed;
		Exception exception;
	}
	
	Result[] dirTests;
	Result[] subpkgTests;
	if (Defines.integrationTestCaseDir.exists)
	{
		writeln("#######################################");
		writeln("## Test Directory Entries            ##");
		writeln("#######################################");
		foreach (de; dirEntries(Defines.integrationTestCaseDir, SpanMode.shallow))
		{
			// 隠しファイルはスキップする
			if (de.name.baseName.startsWith("."))
				continue;
			// ターゲット指定がある場合は、ターゲット指定されている場合だけ実行
			if (config.integrationTestTargets.length > 0
				&& !config.integrationTestTargets.canFind(de.baseName.stripExtension))
				continue;
			auto res = Result(de.name.baseName);
			dispLog("INFO", de.name.baseName, "Directory test start");
			try
				res.executed = dirTest(de.name);
			catch (Exception e)
				res.exception = e;
			dispLog(res.exception ? "FAILED" : "SUCCESS", de.name.baseName);
			dirTests ~= res;
		}
	}
	if (Defines.subPkgs.length)
	{
		writeln("#######################################");
		writeln("## Test SubPackages                  ##");
		writeln("#######################################");
		foreach (pkgName; Defines.subPkgs)
		{
			// ターゲット指定がある場合は、ターゲット指定されている場合だけ実行
			if (config.integrationTestTargets.length > 0
				&& !config.integrationTestTargets.canFind(":" ~ pkgName))
				continue;
			dispLog("INFO", pkgName, "Subpackages test start");
			auto res = Result(pkgName);
			try
				res.executed = subPkgTest(pkgName, "unittest");
			catch (Exception e)
				res.exception = e;
			dispLog(res.exception ? "FAILED" : "SUCCESS", pkgName);
			subpkgTests ~= res;
		}
	}
	
	if (dirTests.length > 0 || subpkgTests.length > 0)
	{
		stdout.flush();
		writeln("#######################################");
		writeln("## Integration Test Summary          ##");
		writeln("#######################################");
	}
	bool failed;
	if (dirTests.length > 0)
	{
		writeln("##### Test Summary of Directory Entries");
		writefln("Failed:    %s / %s", dirTests.count!(a => !!a.exception), dirTests.length);
		writefln("Succeeded: %s / %s", dirTests.count!(a => a.executed), dirTests.length);
		writefln("Skipped:   %s / %s", dirTests.count!(a => !a.executed && !a.exception), dirTests.length);
		foreach (res; dirTests)
		{
			if (res.exception)
			{
				writefln("[X] %s: %s", res.name, res.exception.msg);
				failed = true;
			}
			else if (res.executed)
			{
				writefln("[O] %s", res.name);
			}
			else
			{
				writefln("[-] %s", res.name);
			}
		}
	}
	if (subpkgTests.length > 0)
	{
		writeln("##### Test Summary of SubPackages");
		writefln("Failed:    %s / %s", subpkgTests.count!(a => !!a.exception), subpkgTests.length);
		writefln("Succeeded: %s / %s", subpkgTests.count!(a => a.executed), subpkgTests.length);
		writefln("Skipped:   %s / %s", subpkgTests.count!(a => !a.executed && !a.exception), subpkgTests.length);
		foreach (res; subpkgTests)
		{
			if (res.exception)
			{
				failed = true;
				writefln("[X] %s: %s", res.name, res.exception.msg);
			}
			else if (res.executed)
			{
				writefln("[O] %s", res.name);
			}
			else
			{
				writefln("[-] %s", res.name);
			}
		}
	}
	enforce(!failed, "Integration test was failed.");
}


///
void createArchive()
{
	import std.file;
	auto archiveName = format!"%s-%s-%s-%s%s"(
		config.projectName, config.refName, config.os, config.arch, config.archiveSuffix);
	auto docArchiveName = format!"docs%s"(config.archiveSuffix);
	scope (success)
	{
		if (archiveName.exists)
			writeln("::set-output name=ARCNAME::", archiveName);
		if (docArchiveName.exists)
			writeln("::set-output name=DOCARCNAME::", docArchiveName);
	}
	version (Windows)
	{
		auto zip = new ZipArchive;
		void addZip(string file, string base = getcwd())
		{
			auto m = new ArchiveMember;
			m.expandedData = cast(ubyte[])std.file.read(file);
			m.name = file.absolutePath.relativePath(base.absolutePath);
			m.time = file.timeLastModified();
			m.fileAttributes = file.getAttributes();
			m.compressionMethod = CompressionMethod.deflate;
			zip.addMember(m);
		}
		if ("docs".exists)
		{
			foreach (de; dirEntries("docs", SpanMode.depth))
			{
				if (de.isDir)
					continue;
				addZip(de.name, "docs");
			}
		}
		std.file.write(docArchiveName, zip.build());
	}
	else
	{
		string abs(string file, string base)
		{
			return file.absolutePath.relativePath(absolutePath(base));
		}
		void mv(string from, string to)
		{
			if (from.isDir)
				return;
			if (!to.dirName.exists)
				mkdirRecurse(to.dirName);
			std.file.rename(from, to);
		}
		if ("docs".exists)
		{
			exec(["tar", "cvfz", buildPath("..", docArchiveName), "-C", "."]
				~ dirEntries("docs", "*", SpanMode.shallow)
					.map!(de => abs(de.name, "docs")).array, "docs");
		}
	}
}

///
void exec(string[] args, string workDir = null, string[string] env = null)
{
	import std.process, std.stdio;
	writefln!"> %s"(escapeShellCommand(args));
	auto pid = spawnProcess(args, env, std.process.Config.none, workDir ? workDir : ".");
	auto res = pid.wait();
	enforce(res == 0, format!"Execution was failed[code=%d]."(res));
}
///
void exec(string args, string workDir = null, string[string] env = null)
{
	import std.process, std.stdio;
	writefln!"> %s"(args);
	auto pid = spawnShell(args, env, std.process.Config.none, workDir ? workDir : ".");
	auto res = pid.wait();
	enforce(res == 0, format!"Execution was failed[code=%d]."(res));
}
///
string cmd(string[] args, string workDir = null, string[string] env = null)
{
	import std.process;
	writefln!"> %s"(escapeShellCommand(args));
	auto res = execute(args, env, std.process.Config.none, size_t.max, workDir);
	enforce(res.status == 0, format!"Execution was failed[code=%d]."(res.status));
	return res.output;
}
///
string cmd(string args, string workDir = null, string[string] env = null)
{
	import std.process;
	writefln!"> %s"(args);
	auto res = executeShell(args, env, std.process.Config.none, size_t.max, workDir);
	enforce(res.status == 0, format!"Execution was failed[code=%d]."(res.status));
	return res.output;
}

///
string getRefName()
{
	auto ghref = environment.get("GITHUB_REF");
	enum keyBranche = "refs/heads/";
	enum keyTag = "refs/heads/";
	enum keyPull = "refs/heads/";
	if (ghref.startsWith(keyBranche))
		return ghref[keyBranche.length..$];
	if (ghref.startsWith(keyTag))
		return ghref[keyTag.length..$];
	if (ghref.startsWith(keyPull))
		return "pr" ~ ghref[keyPull.length..$];
	return cmd(["git", "describe", "--tags", "--always"]).chomp;
}

///
string[] getPaths(string[string] env)
{
	version (Windows)
		return env.get("Path", env.get("PATH", env.get("path", null))).split(";");
	else
		return env.get("PATH", null).split(":");
}
///
string[] getPaths()
{
	version (Windows)
		return environment.get("Path").split(";");
	else
		return environment.get("PATH").split(":");
}

///
void setPaths(string[string] env, string[] paths)
{
	version (Windows)
		env["Path"] = paths.join(";");
	else
		env["PATH"] = paths.join(":");
}

///
void setPaths(string[] paths)
{
	version (Windows)
		environment["Path"] = paths.join(";");
	else
		environment["PATH"] = paths.join(":");
}

///
string searchPath(string name, string[] dirs = null)
{
	if (name.length == 0)
		return name;
	if (name.isAbsolute())
		return name;
	
	foreach (dir; dirs.chain(getPaths()))
	{
		version (Windows)
			auto bin = dir.buildPath(name).setExtension(".exe");
		else
			auto bin = dir.buildPath(name);
		if (bin.exists)
			return bin;
	}
	return name;
}

///
void addCurlPath(ref string[string] env)
{
	env[null] = null;
	env.remove(null);
	if (config.os == "windows" && config.arch == "x86_64")
	{
		auto bin64dir = searchDCompiler().dirName.buildNormalizedPath("../bin64");
		if (bin64dir.exists && bin64dir.isDir)
			env["Path"] = bin64dir ~ ";" ~ environment.get("Path").chomp(";");
	}
	else if (config.os == "windows" && config.arch == "x86")
	{
		auto bin32dir = searchDCompiler().dirName.buildNormalizedPath("../bin");
		if (bin32dir.exists && bin32dir.isDir)
			env["Path"] = bin32dir ~ ";" ~ environment.get("Path").chomp(";");
	}
}

///
string searchDCompiler()
{
	auto compiler = config.compiler;
	if (compiler.absolutePath.exists)
		return compiler.absolutePath;
	compiler = compiler.searchPath();
	if (compiler.exists)
		return compiler;
	
	auto dc = searchPath(environment.get("DC"));
	if (dc.exists)
		return dc;
	
	auto dmd = searchPath(environment.get("DMD"));
	if (dmd.exists)
		return dmd;
	
	return "dmd";
}

///
string expandMacro(string str, string[string] map)
{
	return str.replaceAll!(
		a => map.get(a[1], environment.get(a[1], null)))
		(regex(r"\$\{(.+?)\}", "g"));
}
///
string getStr(JSONValue jv, string name, string[string] map, string defaultValue = null)
{
	if (name !in jv)
		return defaultValue;
	return expandMacro(jv[name].str, map);
}
///
string[] getAry(JSONValue jv, string name, string[string] map, string[] defaultValue = null)
{
	if (name !in jv)
		return defaultValue;
	return jv[name].array.map!(v => expandMacro(v.str, map)).array;
}
///
string[string] getObj(JSONValue jv, string name, string[string] map, string[string] defaultValue = null)
{
	if (name !in jv)
		return defaultValue;
	string[string] ret;
	foreach (k, v; jv[name].object)
		ret[k] = expandMacro(v.str, map);
	return ret;
}

///
void dispLog(string severity, string name, string text = null)
{
	uint colorcode;
	switch (severity)
	{
	case "INFO":
		colorcode = 33; // yellow
		break;
	case "ERROR":
	case "FAILED":
		colorcode = 31; // red
		break;
	case "SUCCESS":
		colorcode = 36; // cyan
		break;
	default:
		colorcode = 37; // white
		break;
	}
	writefln("\u001b[%02dm[%s]%s\u001b[0m%s%s", colorcode, severity,
		name.length > 0 ? " " ~ name : name,
		name.length > 0 && text.length > 0 ? ":" : null,
		text.length > 0 ? " " ~ text : null);
}
