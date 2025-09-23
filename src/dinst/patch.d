module dinst.patch;



/*******************************************************************************
 * 64bit絶対ジャンプの書き込み
 * 
 * where の機械語先頭5バイトを書き換えて target へジャンプする。
 * ```
 *      mov rax, imm64  (0x48 0xB8 imm64) ;
 *      jmp rax         (0xFF 0xE0) ;
 * ```
 * Params:
 *      where = 書き換える関数の先頭アドレス
 *      target = 書き換えた関数からジャンプさせる関数の先頭アドレス
 * Returns:
 *      成功したらtrue, 失敗でfalse
 */
// --- 機械語シーケンス作成ヘルパ ---
// 
// 合計 10 + 2 = 12 バイト
bool writeAbsJump(void* where, void* target) @system
{
	auto addr = cast(size_t)target;
	union Dat
	{
		ubyte[12] stub;
		struct MovDat1
		{
		align(1):
			ushort movImm64;
			ulong  func;
			ushort jmp;
		}
		MovDat1 mov1;
		struct MovDat2
		{
		align(1):
			uint high;
			ulong low;
		}
		MovDat2 mov2;
	}
	
	Dat patch;
	patch.mov1 = Dat.MovDat1(0xB848, addr, 0xE0FF);
	
	version (Windows)
	{
		import core.sys.windows.windows;
		DWORD old;
		if (!VirtualProtect(where, 12, PAGE_EXECUTE_READWRITE, &old))
			return false;
		(cast(Dat*)where).mov2.high = patch.mov2.high;
		(cast(Dat*)where).mov2.low  = patch.mov2.low;
		VirtualProtect(where, 12, old, &old);
		// Flush instruction cache so CPU sees new code
		FlushInstructionCache(GetCurrentProcess(), where, 12);
	}
	else version (Posix)
	{
		import core.sys.posix.sys.mman;
		import core.sys.posix.unistd;
		auto pagesize = sysconf(_SC_PAGESIZE);
		if (pagesize <= 0)
			pagesize = 4096;
		auto pageStart = cast(size_t)where & ~(pagesize - 1);
		if (mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
			return false;
		(cast(Dat*)where).mov2.high = patch.mov2.high;
		(cast(Dat*)where).mov2.low  = patch.mov2.low;
		cast(void)mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_EXEC);
		
	}
	return true;
}

/*******************************************************************************
 * 32bit相対ジャンプの書き込み
 * 
 * where の機械語先頭5バイトを書き換えて target へジャンプする
 * ```
 *      jmp rel32  (0xE9 rel32) ;
 * ```
 * Params:
 *      where = 書き換える関数の先頭アドレス
 *      target = 書き換えた関数からジャンプさせる関数の先頭アドレス
 * Returns:
 *      成功したらtrue, 失敗でfalse
 */
bool writeRelJump(void* where, void* target)
{
	auto p = cast(ubyte*)where;
	size_t src = cast(size_t)p;
	size_t dst = cast(size_t)target;

	version (X86)
	{
		// 32ビット幅の場合、範囲チェック不要
		auto rel32 = cast(int)(cast(long)dst - (cast(long)src + 5));
	}
	else version (X86_64)
	{
		// rel32 = target - (where + 5)
		auto rel64 = cast(long)dst - (cast(long)src + 5);
		// 32bit 相対ジャンプの範囲外
		if (rel64 < int.min || rel64 > int.max)
			return false;
		auto rel32 = cast(int)rel64;
	}
	else static assert(0);

	union Dat
	{
		ubyte[5] stub;
		struct MovDat1
		{
		align(1):
			ubyte high;
			int   low;
		}
		MovDat1 mov1;
	}

	// 5 バイトの相対ジャンプを生成: 0xE9 <rel32 little-endian>
	Dat patch;
	patch.mov1 = Dat.MovDat1(0xE9, rel32);
	
	version (Windows)
	{
		import core.sys.windows.windows;
		DWORD tmp;
		// VirtualProtect はページ単位で保護を変更するが、先頭アドレスを渡せば OK
		if (!VirtualProtect(where, 5, PAGE_EXECUTE_READWRITE, &tmp))
			return false;
		(cast(Dat*)where).mov1.high = patch.mov1.high;
		(cast(Dat*)where).mov1.low  = patch.mov1.low;
		// 保護を元に戻す
		VirtualProtect(where, 5, tmp, &tmp);
		
		// 命令キャッシュをフラッシュして CPU が新しい命令を読むようにする
		FlushInstructionCache(GetCurrentProcess(), where, 5);
	}
	else version (Posix)
	{
		import core.sys.posix.sys.mman;
		import core.sys.posix.unistd;
		auto pagesize = sysconf(_SC_PAGESIZE);
		if (pagesize <= 0)
			pagesize = 4096;
		auto pageStart = cast(size_t)where & ~(pagesize - 1);
		if (mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
			return false;
		(cast(Dat*)where).mov1.high = patch.mov1.high;
		(cast(Dat*)where).mov1.low  = patch.mov1.low;
		cast(void)mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_EXEC);
		version (LDC)
		{
			import ldc.intrinsics;
			llvm_clear_cache(where, (cast(ubyte*)where) + 5);
		}
	}
	
	return true;
}

/*******************************************************************************
 * 単純ジャンプ版トランポリン作成
 */
bool writeAbsJmp32(void* where, void* target)
{
	version (X86)
	{
		union Dat
		{
			ubyte[10] stub;
			struct MovDat1
			{
			align(1):
				ushort jmp;
				uint   addr1;
				uint   addr2;
			}
			MovDat1 mov1;
			struct MovDat2
			{
			align(1):
				ulong  high;
				ushort low;
			}
			MovDat2 mov2;
		}
		ubyte* jmpBuf = cast(ubyte*)where;
		size_t addrJmpBuf = cast(size_t)&jmpBuf[6];
		size_t addrJmpTo = cast(size_t)target;
		Dat patch;
		patch.mov1 = Dat.MovDat1(0x25FF, cast(uint)addrJmpBuf, cast(uint)addrJmpTo);
		
		version (Windows)
		{
			import core.sys.windows.windows;
			DWORD tmp;
			// VirtualProtect はページ単位で保護を変更するが、先頭アドレスを渡せば OK
			if (!VirtualProtect(where, 5, PAGE_EXECUTE_READWRITE, &tmp))
				return false;
			(cast(Dat*)where).mov2.high = patch.mov2.high;
			(cast(Dat*)where).mov2.low  = patch.mov2.low;
			// 保護を元に戻す
			VirtualProtect(where, 5, tmp, &tmp);
			
			// 命令キャッシュをフラッシュして CPU が新しい命令を読むようにする
			FlushInstructionCache(GetCurrentProcess(), where, 5);
		}
		else version (Posix)
		{
			import core.sys.posix.sys.mman;
			import core.sys.posix.unistd;
			auto pagesize = sysconf(_SC_PAGESIZE);
			if (pagesize <= 0)
				pagesize = 4096;
			auto pageStart = cast(size_t)where & ~(pagesize - 1);
			if (mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
				return false;
			(cast(Dat*)where).mov2.high = patch.mov2.high;
			(cast(Dat*)where).mov2.low  = patch.mov2.low;
			cast(void)mprotect(cast(void*)pageStart, pagesize, PROT_READ | PROT_EXEC);
			version (LDC)
			{
				import ldc.intrinsics;
				llvm_clear_cache(where, (cast(ubyte*)where) + 5);
			}
		}
		return true;
	}
	else
	{
		return false;
	}
}

/*******************************************************************************
 * トランポリン作成
 * 
 * original の先頭 stolen をコピーし、コピー末尾に戻りジャンプ (original + stolen) を付加する
 */
bool createTrampoline64(void* original, size_t stolen, ubyte[] tramp)
{
	// コピー元の保護を読み取り可能にする（通常はコード領域は読み取れるので省略可）
	foreach (i; 0..stolen)
		(cast(ubyte*)tramp)[i] = (cast(ubyte*)original)[i];
	
	// tramp の末尾に戻りジャンプを書く (absolute jump to original + stolen)
	void* returnAddr = cast(ubyte*)original + stolen;
	return writeAbsJump(cast(ubyte*)tramp + stolen, returnAddr);
}

/*******************************************************************************
 * トランポリン作成32bit版
 * 
 * original の先頭 stolen をコピーし、コピー末尾に戻りジャンプ (original + stolen) を付加する
 */
bool createTrampoline32(void* original, size_t stolen, ubyte[] tramp)
{
	// コピー元の保護を読み取り可能にする（通常はコード領域は読み取れるので省略可）
	foreach (i; 0..stolen)
		(cast(ubyte*)tramp)[i] = (cast(ubyte*)original)[i];
	
	// tramp の末尾に戻りジャンプを書く (absolute jump to original + stolen)
	void* returnAddr = cast(ubyte*)original + stolen;
	return writeAbsJmp32(tramp.ptr + stolen, returnAddr);
}

/*******************************************************************************
 * 単純ジャンプ版トランポリン作成
 * 
 * original の先頭 stolen をコピーし、コピー末尾に戻りジャンプ (original + stolen) を付加する
 */
bool createTrampoline32Jmp(void* jmpTo, ubyte[] tramp)
{
	return writeAbsJmp32(tramp.ptr, jmpTo);
}

/// ditto
bool createTrampoline64Jmp(void* jmpTo, ubyte[] tramp)
{
	return writeAbsJump(tramp.ptr, jmpTo);
}

/*******************************************************************************
 * 最終値がRETのトランポリン作成
 */
bool createTrampoline64Ret(void* original, size_t stolen, ubyte[] tramp)
{
	foreach (i; 0..stolen)
		(cast(ubyte*)tramp)[i] = (cast(ubyte*)original)[i];
	return true;
}


///
struct Stolen
{
	///
	size_t size;
	///
	bool isJmp;
	///
	bool isRet;
	///
	void* addr;
}


/*******************************************************************************
 * Capstone で命令長を解析し、上書きすべきバイト数を決定する
 * 
 * Params:
 *      funcAddr = address of original code
 *      maxRequiredLen = minimum bytes to cover
 * Returns:
 *      ret.size == 0 の場合は失敗
 */
Stolen determineStolenBytes(void* funcAddr, size_t maxRequiredLen = 12)
{
	import dinst.capstone;
	size_t maxScan = 64;
	csh handle;
	cs_err err = cs_open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64, &handle);
	if (err != cs_err.CS_ERR_OK)
		return Stolen.init;
	scope (exit)
		cs_close(&handle);
	// Optionally set syntax or detail if needed
	cs_option(handle, cs_opt_type.CS_OPT_DETAIL, cs_opt_value.CS_OPT_OFF);

	// Read raw bytes from function address
	ubyte[128] code_buf;
	if (maxScan > code_buf.length)
		maxScan = code_buf.length;
	// Make sure memory is readable; we assume it is (code section). Use ReadProcessMemory if needed.
	foreach (i; 0..maxScan)
		code_buf[i] = (cast(ubyte*)funcAddr)[i];

	auto code = code_buf.ptr;
	auto address = cast(ulong)funcAddr;

	cs_insn* insn;
	auto count = cs_disasm(handle, code, maxScan, address, 0, &insn);
	if (count == 0)
		return Stolen.init;
	scope (exit)
		cs_free(insn, count);
		
	size_t acc = 0;
	foreach (i; 0..count)
	{
		enum X86_INS_RET = 633;
		enum X86_INS_RETF = 351;
		enum X86_INS_RETFQ = 352;
		enum X86_INS_JMP = 172;
		acc += insn[i].size;
		//import std.stdio, core.stdc.string;
		//writefln("[%d] %s %s  / size = %d",
		//	acc,
		//	insn[i].mnemonic[0..strlen(insn[i].mnemonic.ptr)],
		//	insn[i].op_str[0..strlen(insn[i].op_str.ptr)],
		//	insn[i].size);
		if (acc >= maxRequiredLen)
		{
			if (insn[i].id == X86_INS_RET || insn[i].id == X86_INS_RETF || insn[i].id == X86_INS_RETFQ)
				return Stolen(acc, false, true, null);
			if (insn[i].id == X86_INS_JMP)
				return Stolen(acc, true, false, cast(void*)(
					cast(size_t)funcAddr + acc
					+ cast(size_t)(insn[i].bytes[1] << 0)
					+ cast(size_t)(insn[i].bytes[2] << 8)
					+ cast(size_t)(insn[i].bytes[3] << 16)
					+ cast(size_t)(insn[i].bytes[4] << 24)));
			return Stolen(acc);
		}
		if (insn[i].id == X86_INS_RET || insn[i].id == X86_INS_RETF || insn[i].id == X86_INS_RETFQ)
			break;
		if (insn[i].id == X86_INS_JMP)
			break;
	}
	
	// not enough instructions in scanned region
	return Stolen.init;
}
