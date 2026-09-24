module dinst.patch;

import dinst.capstone;



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
	else
	{
		int rel32;
		return false;
	}

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

	// コピーした命令列の中に、相対分岐やRIP相対アドレッシングなど
	// 「元のアドレスに依存する」命令が含まれている場合、コピー先の
	// 新しいアドレスに合わせて再配置(オフセットの再計算)する。
	// これを行わないと、例えば glibc の free() 先頭付近にある
	// NULLチェック用の条件分岐(je)が、トランポリンから実行された際に
	// 全く見当違いのアドレスへ飛んでしまい、クラッシュの原因となる。
	if (!relocateStolenBytes(original, tramp.ptr, stolen, cs_mode.CS_MODE_64))
		return false;
	
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

	// 64bit版と同様、コピーした命令列の中に相対分岐(Jcc/JMP/CALL)などの
	// 位置依存命令が含まれる場合、コピー先の新しいアドレスに合わせて
	// 再配置する。32bitコードではRIP相対アドレッシングは存在しないが、
	// 位置独立コード(PIC)でよく使われる `call get_pc_thunk` のような
	// 相対callを含む関数をフックする場合に備え、同じ処理を適用する。
	if (!relocateStolenBytes(original, tramp.ptr, stolen, cs_mode.CS_MODE_32))
		return false;
	
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
	if (!relocateStolenBytes(original, tramp.ptr, stolen, cs_mode.CS_MODE_64))
		return false;
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


/// Capstoneの命令グループ定数(全アーキテクチャ共通)
private enum ubyte CS_GRP_BRANCH_RELATIVE = 7;
private enum ubyte CS_GRP_CALL = 2;
private enum uint X86_INS_RET_ID = 633;

/// insn が指定グループに属するか判定する
private bool hasGroup(const(cs_insn)* insn, ubyte group) @trusted
{
	if (insn.detail is null)
		return false;
	foreach (i; 0 .. insn.detail.groups_count)
		if (insn.detail.groups[i] == group)
			return true;
	return false;
}

/// レジスタ名(Capstoneのcs_reg_nameが返す文字列)から、
/// x86機械語における3bitレジスタ番号(mov r32,imm32 の `B8+reg` 等で使う、
/// eax=0, ecx=1, edx=2, ebx=3, esp=4, ebp=5, esi=6, edi=7)を求める。
/// 該当しなければ -1。
private int x86RegEncoding(const(char)* name) @trusted
{
	import core.stdc.string : strcmp;
	if (name is null)
		return -1;
	if (strcmp(name, "eax") == 0) return 0;
	if (strcmp(name, "ecx") == 0) return 1;
	if (strcmp(name, "edx") == 0) return 2;
	if (strcmp(name, "ebx") == 0) return 3;
	if (strcmp(name, "esp") == 0) return 4;
	if (strcmp(name, "ebp") == 0) return 5;
	if (strcmp(name, "esi") == 0) return 6;
	if (strcmp(name, "edi") == 0) return 7;
	return -1;
}

/*******************************************************************************
 * `target` が、32bit PIC/PIE コードで極めて頻繁に使われる
 * "get_pc_thunk" 関数(`mov reg32, dword ptr [esp]; ret` という
 * 2命令だけの、呼び出し元に「call命令の戻り先アドレス」をそのまま
 * 返すだけの小さなヘルパー関数)かどうかを判定する。
 *
 * 該当する場合、使われているレジスタの機械語エンコード番号(0〜7)を
 * 返す。該当しない場合は -1 を返す。
 */
private int detectGetPcThunk(csh handle, void* target) @system
{
	ubyte[8] buf;
	foreach (i; 0 .. buf.length)
		buf[i] = (cast(ubyte*)target)[i];

	cs_insn* insn;
	auto count = cs_disasm(handle, buf.ptr, buf.length, cast(ulong)target, 2, &insn);
	scope (exit)
		if (count) cs_free(insn, count);

	if (count < 2)
		return -1;
	if (insn[0].detail is null)
		return -1;
	if (insn[1].id != X86_INS_RET_ID)
		return -1;

	const(cs_x86)* x86 = &insn[0].detail.x86;
	if (x86.op_count != 2)
		return -1;
	if (x86.operands[0].type != x86_op_type.X86_OP_REG)
		return -1;
	if (x86.operands[1].type != x86_op_type.X86_OP_MEM)
		return -1;
	if (x86.operands[1].mem.index != X86_REG_INVALID)
		return -1;
	if (x86.operands[1].mem.disp != 0)
		return -1;

	auto baseName = cs_reg_name(handle, cast(uint)x86.operands[1].mem.base);
	import core.stdc.string : strcmp;
	if (baseName is null || strcmp(baseName, "esp") != 0)
		return -1;

	auto regName = cs_reg_name(handle, cast(uint)x86.operands[0].reg);
	return x86RegEncoding(regName);
}

/*******************************************************************************
 * 位置依存命令(相対分岐・RIP相対アドレッシング)1つを、コピー先の新しい
 * アドレスに合わせて再配置する。
 *
 * 対応するもの:
 * - 相対分岐(Jcc/JMPの直接相対形式): Capstoneの
 *   `CS_GRP_BRANCH_RELATIVE` グループで判別する。Capstoneは既に
 *   ジャンプ先の絶対アドレスを operands[0].imm に解決済みなので、
 *   コピー先の命令アドレスから見た新しい相対オフセットを計算し直し、
 *   `encoding.imm_offset`/`imm_size` が示す位置のバイトを書き換える。
 *   短い形式(rel8, 1バイト)でオフセットが収まらない場合は
 *   再配置不能として失敗を返す(命令の再エンコード/拡張は行わない)。
 * - RIP相対のメモリオペランド(例: `mov rax, [rip+disp]`):
 *   参照先の絶対アドレスを維持するよう、`encoding.disp_offset`が
 *   示す位置の32bit変位を書き換える。
 * - `call get_pc_thunk_XX`(32bit PICコードでのGOTベース取得の定型句):
 *   呼び出し先が本当に「戻り先アドレスをそのまま返すだけ」の
 *   関数(get_pc_thunk)であることを`detectGetPcThunk`で確認できた
 *   場合に限り、call命令(5バイト: `E8 rel32`)を、call/retを
 *   一切実行せずに同じ結果が得られる `mov reg32, imm32`
 *   (これも5バイト: `B8+reg imm32`)に置き換える。
 *   `imm32`には、この命令が「元の(コピーされる前の)アドレスで」
 *   実行された場合にget_pc_thunkが返していたはずの値
 *   (=call命令の直後のアドレス)をそのまま埋め込む。
 *   call+ret(push+pop)は差し引きスタックに影響を残さないため、
 *   単純な mov 1個に置き換えても後続コードの前提を壊さない。
 *   get_pc_thunk以外の呼び出し先を持つcall命令は、安全に補正する
 *   方法が無いため再配置不可能として失敗を返す。
 *
 * 上記以外の、位置に依存しない通常の命令は何もせず true を返す。
 *
 * Params:
 *      insn = コピー元(original)を基準に解析した命令情報
 *      newInstrAddr = コピー先でこの命令が配置される先頭アドレス
 *      instrBytes = コピー先に既にコピー済みの、この命令のバイト列
 *                   (この関数がその場で書き換える)
 * Returns:
 *      再配置できた(または再配置が不要だった)ら true、
 *      安全に再配置できないと判断したら false。
 */
private bool relocateOneInstruction(csh handle, const(cs_insn)* insn,
	void* newInstrAddr, ubyte[] instrBytes) @system
{
	import core.stdc.string : strcmp;

	if (insn.detail is null)
		return false; // 詳細情報が無いと安全性を判断できない

	const(cs_x86)* x86 = &insn.detail.x86;

	if (hasGroup(insn, CS_GRP_CALL))
	{
		// 相対call(E8 rel32)以外(レジスタ間接call等)は非対応。
		if (x86.op_count != 1 || x86.operands[0].type != x86_op_type.X86_OP_IMM)
			return false;

		void* callTarget = cast(void*)x86.operands[0].imm;
		int regEncoding = detectGetPcThunk(handle, callTarget);
		if (regEncoding < 0)
			return false; // get_pc_thunk以外は安全に補正できない

		// call命令(5バイト)を、get_pc_thunkが返すはずだった値
		// (元のアドレスでのcall直後のアドレス)を直接埋め込んだ
		// mov reg32, imm32(同じく5バイト)に置き換える。
		if (instrBytes.length != 5)
			return false;
		uint originalReturnAddr = cast(uint)(insn.address + insn.size);
		instrBytes[0] = cast(ubyte)(0xB8 + regEncoding);
		*cast(uint*)(instrBytes.ptr + 1) = originalReturnAddr;
		return true;
	}

	if (hasGroup(insn, CS_GRP_BRANCH_RELATIVE))
	{
		// 直接相対のjmp/jcc。オペランドは通常1つで、
		// Capstoneが計算済みの絶対アドレスが operands[0].imm に入っている。
		if (x86.op_count != 1 || x86.operands[0].type != x86_op_type.X86_OP_IMM)
			return false;
		if (x86.encoding.imm_size == 0)
			return false;

		long target = x86.operands[0].imm;
		long newEnd = cast(long)newInstrAddr + insn.size;
		long newRel = target - newEnd;

		if (x86.encoding.imm_size == 1)
		{
			// rel8(短い形式)。再配置後のオフセットが1バイトに
			// 収まらない場合は、命令の再エンコードは行わず安全に失敗する。
			if (newRel < byte.min || newRel > byte.max)
				return false;
			instrBytes[x86.encoding.imm_offset] = cast(ubyte)cast(byte)newRel;
			return true;
		}
		else if (x86.encoding.imm_size == 4)
		{
			if (newRel < int.min || newRel > int.max)
				return false;
			*cast(int*)(instrBytes.ptr + x86.encoding.imm_offset) = cast(int)newRel;
			return true;
		}
		return false; // 想定外のサイズ
	}

	// RIP相対のメモリオペランド(例: `mov rax, [rip+disp]`、`lea rax, [rip+disp]`)
	foreach (i; 0 .. x86.op_count)
	{
		if (x86.operands[i].type != x86_op_type.X86_OP_MEM)
			continue;
		if (x86.operands[i].mem.index != X86_REG_INVALID)
			continue; // index併用の複雑な形式は非対応
		if (x86.operands[i].mem.base == X86_REG_INVALID)
			continue;
		const(char)* baseName = cs_reg_name(handle, cast(uint)x86.operands[i].mem.base);
		if (baseName is null || strcmp(baseName, "rip") != 0)
			continue;
		if (x86.encoding.disp_size != 4)
			return false; // 想定外のエンコーディング

		long originalTarget = cast(long)insn.address + insn.size + x86.operands[i].mem.disp;
		long newEnd = cast(long)newInstrAddr + insn.size;
		long newDisp = originalTarget - newEnd;
		if (newDisp < int.min || newDisp > int.max)
			return false;
		*cast(int*)(instrBytes.ptr + x86.encoding.disp_offset) = cast(int)newDisp;
		return true;
	}

	return true; // 再配置不要な命令
}

/*******************************************************************************
 * `original` から `dest` へコピーされた `stolenSize` バイト分の命令列を、
 * 新しい配置先アドレスに合わせて再配置する。
 *
 * `original` の内容を改めて逆アセンブルし(コピー元のアドレスを基準に
 * 絶対ターゲットを正しく解決するため)、各命令ごとに
 * `relocateOneInstruction` を適用して `dest` 側のバイト列を書き換える。
 *
 * Params:
 *      mode = 逆アセンブルするアーキテクチャモード
 *             (`CS_MODE_64`=x86_64, `CS_MODE_32`=x86 32bit)。
 *             呼び出し元の実行環境(32bit/64bit)に合わせて指定すること。
 *
 * Returns:
 *      すべての命令を安全に再配置(または再配置不要と判断)できたら true。
 *      再配置できない命令が1つでもあれば false
 *      (この場合、呼び出し元は不正なトランポリンを使わずに失敗として扱うこと)。
 */
private bool relocateStolenBytes(void* original, void* dest, size_t stolenSize, cs_mode mode) @system
{
	if (stolenSize == 0)
		return true;

	csh handle;
	if (cs_open(cs_arch.CS_ARCH_X86, mode, &handle) != cs_err.CS_ERR_OK)
		return false;
	scope (exit)
		cs_close(&handle);
	if (cs_option(handle, cs_opt_type.CS_OPT_DETAIL, cs_opt_value.CS_OPT_ON) != cs_err.CS_ERR_OK)
		return false;

	ubyte[128] buf;
	size_t n = stolenSize < buf.length ? stolenSize : buf.length;
	foreach (i; 0 .. n)
		buf[i] = (cast(ubyte*)original)[i];

	cs_insn* insn;
	auto count = cs_disasm(handle, buf.ptr, n, cast(ulong)original, 0, &insn);
	if (count == 0)
		return false;
	scope (exit)
		cs_free(insn, count);

	size_t acc = 0;
	foreach (i; 0 .. count)
	{
		if (acc + insn[i].size > stolenSize)
			break; // 盗んだ範囲を超える分は対象外
		void* newInstrAddr = cast(ubyte*)dest + acc;
		ubyte[] instrBytes = (cast(ubyte*)dest + acc)[0 .. insn[i].size];
		if (!relocateOneInstruction(handle, &insn[i], newInstrAddr, instrBytes))
			return false;
		acc += insn[i].size;
	}
	return true;
}


/*******************************************************************************
 * jmp命令のオペランド情報(Capstoneのdetail)から、実際のジャンプ先アドレスを求める
 * 
 * 対応するオペランド形式:
 * - 即値 (例: `jmp rel32` / `jmp rel8`)
 *   Capstoneはこれを解析した時点でジャンプ先の絶対アドレスまで計算し、
 *   operands[0].imm に格納しているため、そのまま使用できる。
 * - RIP相対のメモリ間接参照 (例: `jmp qword ptr [rip+disp32]`)
 *   これはPLT/GOT経由の関数呼び出しスタブ(共有ライブラリ関数へのポインタなど)で
 *   典型的に使われる形式。まず `[rip+disp]` が指すアドレス(=GOTスロットのアドレス)を
 *   計算し、そのスロットの中身(8バイト)を読むことで初めて本当のジャンプ先が得られる。
 * 
 * 上記以外(レジスタ間接 `jmp rax` や、base/indexにRIP以外のレジスタを使う形式など)は
 * 静的には解決できないため、安全のため null を返す。
 * 
 * Params:
 *      handle = CS_OPT_DETAIL を ON にした capstone ハンドル
 *      insn   = 解析対象の jmp 命令
 * Returns:
 *      解決できたジャンプ先アドレス。解決できない場合は null。
 */
private void* resolveJmpTarget(csh handle, const(cs_insn)* insn) @system
{
	import core.stdc.string : strcmp;

	if (insn.detail is null)
		return null;
	const(cs_x86)* x86 = &insn.detail.x86;
	// jmp命令のオペランドは通常1つ。それ以外は想定外のためフォールバック。
	if (x86.op_count != 1)
		return null;
	const(cs_x86_op)* op = &x86.operands[0];
	final switch (op.type)
	{
	case x86_op_type.X86_OP_IMM:
		// 直接ジャンプ(相対/絶対)。Capstoneが計算済みの絶対アドレスをそのまま使う。
		return cast(void*)op.imm;
	case x86_op_type.X86_OP_MEM:
		// index レジスタを使う形式 (jmp [base+index*scale+disp]) は非対応。
		if (op.mem.index != X86_REG_INVALID)
			return null;
		// baseレジスタが無い、またはRIP以外の場合は非対応
		// (絶対アドレス直参照やbaseレジスタ相対は静的に解決できないため)
		if (op.mem.base == X86_REG_INVALID)
			return null;
		const(char)* baseName = cs_reg_name(handle, cast(uint)op.mem.base);
		if (baseName is null || strcmp(baseName, "rip") != 0)
			return null;
		// `[rip+disp]` の指すアドレス = 命令末尾 + disp。ここがGOTスロットに相当する。
		void** gotSlot = cast(void**)(insn.address + insn.size + op.mem.disp);
		// GOTスロットの中身(=実際の関数アドレス)を読む。
		// NOTE: 遅延バインディング(lazy binding)が未解決のままだと、ここには
		// リンカのリゾルバスタブのアドレスが入っている可能性がある。
		// 一般的なLinuxディストリビューションの既定(-z now / フルRELRO)では
		// プログラム開始前に解決済みのため問題にならない。
		return *gotSlot;
	case x86_op_type.X86_OP_REG:
		// `jmp rax` のようなレジスタ間接は実行時の値次第で静的に解決不可能。
		return null;
	case x86_op_type.X86_OP_INVALID:
		return null;
	}
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
	size_t maxScan = 64;
	csh handle;
	cs_err err = cs_open(cs_arch.CS_ARCH_X86, cs_mode.CS_MODE_64, &handle);
	if (err != cs_err.CS_ERR_OK)
		return Stolen.init;
	scope (exit)
		cs_close(&handle);
	// jmp/call等のオペランド(ジャンプ先アドレスなど)を取得するために詳細情報を有効化する
	if (cs_option(handle, cs_opt_type.CS_OPT_DETAIL, cs_opt_value.CS_OPT_ON) != cs_err.CS_ERR_OK)
		return Stolen.init;

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
			{
				void* target = resolveJmpTarget(handle, &insn[i]);
				// ジャンプ先を静的に解決できない場合、不正なアドレスへ
				// トランポリンを作ってしまうより安全に失敗させる。
				if (target is null)
					return Stolen.init;
				return Stolen(acc, true, false, target);
			}
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

// テスト用: 実行可能なメモリページを確保/解放する(Windows/POSIX両対応)
version (unittest)
{
	private void* allocExecPage(size_t size) @system
	{
		version (Windows)
		{
			import core.sys.windows.windows : VirtualAlloc, MEM_COMMIT, MEM_RESERVE,
				PAGE_EXECUTE_READWRITE;
			return VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		else version (Posix)
		{
			import core.sys.posix.sys.mman : mmap, MAP_FAILED, MAP_PRIVATE, MAP_ANON,
				PROT_READ, PROT_WRITE, PROT_EXEC;
			auto p = mmap(null, size, PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_ANON, -1, 0);
			return p is MAP_FAILED ? null : p;
		}
		else
			static assert(0, "allocExecPage: unsupported platform");
	}

	private void freeExecPage(void* p, size_t size) @system
	{
		version (Windows)
		{
			import core.sys.windows.windows : VirtualFree, MEM_RELEASE;
			VirtualFree(p, 0, MEM_RELEASE);
		}
		else version (Posix)
		{
			import core.sys.posix.sys.mman : munmap;
			munmap(p, size);
		}
		else
			static assert(0, "freeExecPage: unsupported platform");
	}
}

// PLT/GOT経由の関数(共有ライブラリからインポートされた関数など)は、
// `endbr64; jmp qword ptr [rip+disp32]` のようなスタブを経由してアクセスされることが多い。
// このテストは、そのようなRIP相対の間接jmpを正しく解決できることを検証する。
// (修正前は `jmp` のオペランドを生バイト列から誤って解釈しており、
//  この形式では全く無関係なアドレスを算出してしまっていた)
version (X86_64)
@system unittest
{
	extern(C) static int dummyTarget(int x) @nogc nothrow
	{
		return x + 42;
	}

	enum pageSize = 4096;
	void* mem = allocExecPage(pageSize);
	assert(mem !is null);
	scope (exit)
		freeExecPage(mem, pageSize);

	ubyte* p = cast(ubyte*)mem;
	// endbr64
	p[0..4] = [0xF3, 0x0F, 0x1E, 0xFA];
	// jmp qword ptr [rip+disp32]  (opcode: FF /4)
	p[4] = 0xFF;
	p[5] = 0x25;
	// GOTスロットに見立てた領域を、jmp命令の直後(16バイトアライン位置)に置く
	void** gotSlot = cast(void**)(p + 16);
	*gotSlot = cast(void*)&dummyTarget;
	int disp = cast(int)(cast(long)gotSlot - cast(long)(p + 10));
	*cast(int*)(p + 6) = disp;

	auto stolen = determineStolenBytes(mem, 5);
	assert(stolen.size != 0,
		"PLT風のRIP相対jmpスタブを解決できなかった(修正が効いていない)");
	assert(stolen.isJmp);
	assert(stolen.addr == cast(void*)&dummyTarget,
		"解決したジャンプ先アドレスが実際の関数アドレスと一致しない");
}

// 直接相対jmp (`E9 rel32`) について、後方(負のオフセット)ジャンプでも
// 正しいアドレスを算出できることを検証する。
// (修正前は符号拡張しておらず、後方ジャンプで全く異なるアドレスを算出していた)
version (X86_64)
@system unittest
{
	enum pageSize = 4096;
	void* mem = allocExecPage(pageSize);
	assert(mem !is null);
	scope (exit)
		freeExecPage(mem, pageSize);

	ubyte* p = cast(ubyte*)mem;
	// 後方(このページより手前側)を指す、負のオフセットのジャンプ先。
	// このアドレスは実際に読み書きせず、算出値の比較にのみ使う。
	void* fakeTarget = p - 0x1000;
	p[0] = 0xE9;
	int rel = cast(int)(cast(long)fakeTarget - cast(long)(p + 5));
	assert(rel < 0, "このテストは負のオフセットを検証する意図なので前提が崩れている");
	*cast(int*)(p + 1) = rel;

	auto stolen = determineStolenBytes(mem, 5);
	assert(stolen.size != 0);
	assert(stolen.isJmp);
	assert(stolen.addr == fakeTarget,
		"後方(負オフセット)への直接相対jmpのアドレス計算が誤っている");
}
