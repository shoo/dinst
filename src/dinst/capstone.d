module dinst.capstone;

import core.stdc.stdint : uint8_t, uint16_t, uint64_t;

extern(C):

alias csh = size_t;
alias cs_detail = int;

/// cs_err enum
enum cs_err : int {
	CS_ERR_OK = 0,
	CS_ERR_MEM,
	CS_ERR_ARCH,
	CS_ERR_HANDLE,
	CS_ERR_CSH,
	CS_ERR_MODE,
	CS_ERR_OPTION,
	CS_ERR_DETAIL,
	CS_ERR_MEMSETUP,
	CS_ERR_VERSION,
	CS_ERR_DIET,
	CS_ERR_SKIPDATA,
	CS_ERR_X86_ATT,
	CS_ERR_X86_INTEL,
	CS_ERR_X86_MASM
}

/// cs_arch enum
enum cs_arch : int {
	CS_ARCH_ARM = 0,
	CS_ARCH_ARM64,
	CS_ARCH_MIPS,
	CS_ARCH_X86,
	CS_ARCH_PPC,
	CS_ARCH_SPARC,
	CS_ARCH_SYSZ,
	CS_ARCH_XCORE,
	CS_ARCH_M68K,
	CS_ARCH_TMS320C64X,
	CS_ARCH_M680X,
	CS_ARCH_EVM,
	CS_ARCH_MOS65XX,
	CS_ARCH_WASM,
	CS_ARCH_BPF,
	CS_ARCH_RISCV,
	CS_ARCH_SH,
	CS_ARCH_TRICORE,
	CS_ARCH_MAX,
	CS_ARCH_ALL = 0xFFFF
}

/// cs_mode enum
enum cs_mode : uint {
	CS_MODE_LITTLE_ENDIAN = 0,
	CS_MODE_ARM = 0,
	CS_MODE_16 = 1 << 1,
	CS_MODE_32 = 1 << 2,
	CS_MODE_64 = 1 << 3,
	CS_MODE_THUMB = 1 << 4,
	CS_MODE_MCLASS = 1 << 5,
	CS_MODE_V8 = 1 << 6,
	CS_MODE_MICRO = 1 << 4,
	CS_MODE_MIPS3 = 1 << 5,
	CS_MODE_MIPS32R6 = 1 << 6,
	CS_MODE_MIPS2 = 1 << 7,
	CS_MODE_V9 = 1 << 4,
	CS_MODE_QPX = 1 << 4,
	CS_MODE_SPE = 1 << 5,
	CS_MODE_BOOKE = 1 << 6,
	CS_MODE_PS = 1 << 7,
	CS_MODE_M68K_000 = 1 << 1,
	CS_MODE_M68K_010 = 1 << 2,
	CS_MODE_M68K_020 = 1 << 3,
	CS_MODE_M68K_030 = 1 << 4,
	CS_MODE_M68K_040 = 1 << 5,
	CS_MODE_M68K_060 = 1 << 6,
	CS_MODE_BIG_ENDIAN = 1U << 31,
	CS_MODE_MIPS32 = CS_MODE_32,
	CS_MODE_MIPS64 = CS_MODE_64,
	CS_MODE_M680X_6301 = 1 << 1,
	CS_MODE_M680X_6309 = 1 << 2,
	CS_MODE_M680X_6800 = 1 << 3,
	CS_MODE_M680X_6801 = 1 << 4,
	CS_MODE_M680X_6805 = 1 << 5,
	CS_MODE_M680X_6808 = 1 << 6,
	CS_MODE_M680X_6809 = 1 << 7,
	CS_MODE_M680X_6811 = 1 << 8,
	CS_MODE_M680X_CPU12 = 1 << 9,
	CS_MODE_M680X_HCS08 = 1 << 10,
	CS_MODE_BPF_CLASSIC = 0,
	CS_MODE_BPF_EXTENDED = 1 << 0,
	CS_MODE_RISCV32 = 1 << 0,
	CS_MODE_RISCV64 = 1 << 1,
	CS_MODE_RISCVC = 1 << 2,
	CS_MODE_MOS65XX_6502 = 1 << 1,
	CS_MODE_MOS65XX_65C02 = 1 << 2,
	CS_MODE_MOS65XX_W65C02 = 1 << 3,
	CS_MODE_MOS65XX_65816 = 1 << 4,
	CS_MODE_MOS65XX_65816_LONG_M = 1 << 5,
	CS_MODE_MOS65XX_65816_LONG_X = 1 << 6,
	CS_MODE_MOS65XX_65816_LONG_MX = CS_MODE_MOS65XX_65816_LONG_M | CS_MODE_MOS65XX_65816_LONG_X,
	CS_MODE_SH2 = 1 << 1,
	CS_MODE_SH2A = 1 << 2,
	CS_MODE_SH3 = 1 << 3,
	CS_MODE_SH4 = 1 << 4,
	CS_MODE_SH4A = 1 << 5,
	CS_MODE_SHFPU = 1 << 6,
	CS_MODE_SHDSP = 1 << 7,
	CS_MODE_TRICORE_110 = 1 << 1,
	CS_MODE_TRICORE_120 = 1 << 2,
	CS_MODE_TRICORE_130 = 1 << 3,
	CS_MODE_TRICORE_131 = 1 << 4,
	CS_MODE_TRICORE_160 = 1 << 5,
	CS_MODE_TRICORE_161 = 1 << 6,
	CS_MODE_TRICORE_162 = 1 << 7
}

/// cs_opt_type enum
enum cs_opt_type : int {
	CS_OPT_INVALID = 0,
	CS_OPT_SYNTAX,
	CS_OPT_DETAIL,
	CS_OPT_MODE,
	CS_OPT_MEM,
	CS_OPT_SKIPDATA,
	CS_OPT_SKIPDATA_SETUP,
	CS_OPT_MNEMONIC,
	CS_OPT_UNSIGNED,
	CS_OPT_NO_BRANCH_OFFSET
}

/// Runtime option value (associated with option type above)
enum cs_opt_value
{
	CS_OPT_OFF = 0,
	CS_OPT_ON = 3,
	CS_OPT_SYNTAX_DEFAULT = 0,
	CS_OPT_SYNTAX_INTEL,
	CS_OPT_SYNTAX_ATT,
	CS_OPT_SYNTAX_NOREGNAME,
	CS_OPT_SYNTAX_MASM,
	CS_OPT_SYNTAX_MOTOROLA,
}

/// cs_insn struct
enum CS_MNEMONIC_SIZE = 32; // デフォルト値
struct cs_insn {
	uint id;
	uint64_t address;
	uint16_t size;
	uint8_t[24] bytes;
	char[CS_MNEMONIC_SIZE] mnemonic;
	char[160] op_str;
	cs_detail* detail;
}


/// 関数バインディング
cs_err cs_open(cs_arch arch, cs_mode mode, csh* handle);
cs_err cs_option(csh handle, cs_opt_type type, size_t value);
size_t cs_disasm(csh handle,
                 const(uint8_t)* code, size_t code_size,
                 uint64_t address,
                 size_t count,
                 cs_insn** insn);
void cs_free(cs_insn* insn, size_t count);
cs_err cs_close(csh* handle);

