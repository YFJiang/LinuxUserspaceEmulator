#pragma once

#include <cmath>

#include "SoftMMU.h"

#include <array>
#include <iosfwd>
#include <set>
#include <vector>

namespace LUE {

class Emulator;

class SoftCPU64 {
public:
    enum Register : int {
        RAX,
        RCX,
        RDX,
        RBX,
        RSP,
        RBP,
        RSI,
        RDI,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
    };

    explicit SoftCPU64(Emulator&);

    void set_rip(u64 value) { m_rip = value; }
    u64 rip() const { return m_rip; }

    u64 reg(Register reg) const { return m_gpr[static_cast<size_t>(reg)]; }
    u64 reg(int reg) const { return m_gpr[static_cast<size_t>(reg & 15)]; }
    void set_reg(Register reg, u64 value) { m_gpr[static_cast<size_t>(reg)] = value; }
    void set_reg(int reg, u64 value) { m_gpr[static_cast<size_t>(reg & 15)] = value; }

    u64 rflags() const { return m_rflags; }
    void set_rflags(u64 value) { m_rflags = value; }
    void set_fs_base(u64 value) { m_fs_base = value; }
    void set_gs_base(u64 value) { m_gs_base = value; }
    u64 fs_base() const { return m_fs_base; }
    u64 gs_base() const { return m_gs_base; }

    void step();
    void dump(std::ostream&) const;
    void trace_current_instruction(std::ostream&) const;
    std::string current_instruction_text() const;
    const std::vector<u64>& call_stack() const { return m_call_stack; }
    void push_synthetic_return(u64 return_address) { m_call_stack.push_back(return_address); }

private:
    struct Prefixes {
        bool operand16 { false };
        bool address32 { false };
        bool repz { false };
        bool repnz { false };
        bool lock { false };
        int segment { -1 };
        bool rex_present { false };
        u8 rex { 0 };

        bool rex_w() const { return rex & 0x8; }
        int rex_r() const { return (rex & 0x4) ? 8 : 0; }
        int rex_x() const { return (rex & 0x2) ? 8 : 0; }
        int rex_b() const { return (rex & 0x1) ? 8 : 0; }
    };

    struct ModRM {
        u8 byte { 0 };
        int mod { 0 };
        int reg { 0 };
        int rm { 0 };
        bool is_register() const { return mod == 3; }
    };

    struct Operand {
        bool is_register { true };
        int reg { 0 };
        u64 address { 0 };
        bool rip_relative { false };
        i64 rip_displacement { 0 };
    };

    struct DecodedAddress {
        u64 address { 0 };
        bool rip_relative { false };
        i64 rip_displacement { 0 };
    };

    u8 fetch8();
    u16 fetch16();
    u32 fetch32();
    u64 fetch64();
    i8 fetch_i8() { return static_cast<i8>(fetch8()); }
    i32 fetch_i32() { return static_cast<i32>(fetch32()); }

    Prefixes read_prefixes();
    ModRM fetch_modrm(const Prefixes&);
    Operand decode_rm_operand(const Prefixes&, const ModRM&);
    DecodedAddress decode_memory_address(const Prefixes&, const ModRM&);

    int operand_width(const Prefixes&) const;
    u64 effective_address(const Operand&) const;
    u64 read_operand(const Operand&, int width, const Prefixes&) const;
    void write_operand(const Operand&, int width, u64 value, const Prefixes&);
    u64 read_gpr(int reg, int width, const Prefixes&) const;
    void write_gpr(int reg, int width, u64 value, const Prefixes&);

    // Shadow (taint) tracking. A register byte is "uninitialized" when its shadow
    // lane is non-zero. These mirror read_gpr/write_gpr's width and high-byte
    // semantics so register taint follows the same aliasing rules as the value.
    u64 gpr_shadow(int reg, int width, const Prefixes&) const;
    void set_gpr_shadow(int reg, int width, u64 shadow, const Prefixes&);

    void push64(u64 value, u64 shadow = 0);
    u64 pop64();
    ValueWithShadow<u64> pop64_with_shadow();

    u64 mask_for_width(int width) const;
    u64 sign_bit_for_width(int width) const;
    u64 sign_extend(u64 value, int width) const;

    void set_logic_flags(u64 result, int width);
    u64 add(u64 lhs, u64 rhs, int width, bool carry);
    u64 sub(u64 lhs, u64 rhs, int width, bool borrow);
    bool condition(int cc) const;
    bool branch_condition(int cc);
    void set_flag(u64 flag, bool value);
    bool flag(u64 flag) const;

    // Mark the flags as derived from uninitialized data based on the operands read
    // by the current instruction, so a later conditional branch can be reported.
    void update_flags_taint();
    void warn_uninitialized_read(u64 address) const;
    void warn_uninitialized_pointer(u64 address) const;
    void warn_uninitialized_branch() const;

    void execute_alu_rm_reg(u8 opcode, const Prefixes&);
    void execute_alu_imm(u8 group, const Prefixes&);
    void execute_group_ff(const Prefixes&);
    void execute_group_f6_f7(u8 opcode, const Prefixes&);
    void execute_shift_group(u8 opcode, const Prefixes&);
    void execute_0f(const Prefixes&);
    void execute_string_instruction(u8 opcode, const Prefixes&);

    std::array<u8, 16>& xmm(int index) { return m_xmm[static_cast<size_t>(index & 15)]; }
    const std::array<u8, 16>& xmm(int index) const { return m_xmm[static_cast<size_t>(index & 15)]; }
    void read_xmm_from_operand(const Operand&, std::array<u8, 16>&, const Prefixes&) const;
    void write_xmm_to_operand(const Operand&, const std::array<u8, 16>&, const Prefixes&);

    void execute_x87(u8 opcode, const Prefixes&);
    // Scalar/packed SSE floating-point (single and double). The data kind is
    // selected by the legacy SSE prefix: F3 = scalar single, F2 = scalar double,
    // 66 = packed double, none = packed single.
    void execute_sse_float(u8 opcode, const Prefixes&);
    // Set the integer EFLAGS (ZF/PF/CF, clearing OF/SF/AF) from an ordered
    // floating-point comparison, shared by (U)COMISS/SD and FCOMI/FUCOMI.
    void set_eflags_from_float_compare(long double a, long double b);

    // x87 FPU state -----------------------------------------------------------
    // The x87 stack is 8 entries; each is stored as a host long double (80-bit
    // on x86 Linux, matching the x87 extended precision format).
    std::array<long double, 8> m_fpu_st {};
    // Tag word: 0 = valid, 3 = empty (we use a simple "empty" flag per slot).
    std::array<bool, 8> m_fpu_empty {};
    // Top-of-stack index (ST(0) lives at m_fpu_st[m_fpu_top]).
    int m_fpu_top { 0 };
    u16 m_fpu_status { 0 };   // FSW
    u16 m_fpu_control { 0x037f }; // FCW – double-extended, round-nearest, all exceptions masked
    u8  m_fpu_opcode  { 0 };  // last x87 opcode (low 11 bits)

    // x87 register helpers
    long double& fst(int i)       { return m_fpu_st[static_cast<size_t>((m_fpu_top + i) & 7)]; }
    const long double& fst(int i) const { return m_fpu_st[static_cast<size_t>((m_fpu_top + i) & 7)]; }
    bool& fst_empty(int i)        { return m_fpu_empty[static_cast<size_t>((m_fpu_top + i) & 7)]; }
    bool  fst_empty(int i) const  { return m_fpu_empty[static_cast<size_t>((m_fpu_top + i) & 7)]; }
    void fpu_push(long double v) {
        m_fpu_top = (m_fpu_top - 1) & 7;
        m_fpu_st[static_cast<size_t>(m_fpu_top)] = v;
        m_fpu_empty[static_cast<size_t>(m_fpu_top)] = false;
    }
    long double fpu_pop() {
        long double v = m_fpu_st[static_cast<size_t>(m_fpu_top)];
        m_fpu_empty[static_cast<size_t>(m_fpu_top)] = true;
        m_fpu_top = (m_fpu_top + 1) & 7;
        return v;
    }
    // Compose the architectural FSW: the cached condition/exception bits plus the
    // current top-of-stack pointer in bits 11-13.
    u16 fpu_status_word() const {
        return static_cast<u16>((m_fpu_status & ~(7u << 11)) | ((static_cast<u16>(m_fpu_top) & 7u) << 11));
    }
    void fpu_update_status(long double result) {
        // Update C1 (rounding indicator) – clear it for now.
        m_fpu_status &= ~(1u << 9);
        // Update C3/C2/C0 condition bits for zero/infinity/NaN detection.
        if (std::isnan(result))     m_fpu_status |=  (1u << 0); // C0 = invalid op indicator
        else                         m_fpu_status &= ~(1u << 0);
    }
    // Update FCOM/FUCOM flags into C3/C2/C0 of FSW.
    void fpu_compare(long double a, long double b) {
        m_fpu_status &= ~((1u<<14)|(1u<<10)|(1u<<8)); // clear C3,C2,C0
        if (std::isnan(a) || std::isnan(b)) {
            m_fpu_status |= (1u<<14)|(1u<<10)|(1u<<8); // C3=C2=C0=1 (unordered)
        } else if (a > b) {
            /* C3=0, C2=0, C0=0 -- greater */
        } else if (a < b) {
            m_fpu_status |= (1u<<8); // C0=1 (less)
        } else {
            m_fpu_status |= (1u<<14); // C3=1 (equal)
        }
    }

    [[noreturn]] void unsupported(std::string message) const;
    std::string describe_current_instruction() const;

    Emulator& m_emulator;
    SoftMMU& m_mmu;
    std::array<u64, 16> m_gpr {};
    // Per-register shadow: lane byte non-zero == that register byte is uninitialized.
    std::array<u64, 16> m_gpr_shadow {};
    std::array<std::array<u8, 16>, 16> m_xmm {};
    u32 m_mxcsr { 0x1f80 };
    u64 m_rip { 0 };
    u64 m_rflags { 0x202 };
    u64 m_fs_base { 0 };
    u64 m_gs_base { 0 };

    u64 m_instruction_start { 0 };
    u64 m_decode_pc { 0 };
    std::vector<u64> m_call_stack;

    // Taint state. m_current_taint accumulates "did any operand read by the
    // instruction now executing come from uninitialized storage"; it is reset at
    // the start of every step() and consumed by operand writes. m_flags_tainted is
    // sticky across instructions, mirroring how the real FLAGS register persists.
    mutable bool m_current_taint { false };
    bool m_flags_tainted { false };
    mutable std::set<u64> m_reported_uninit_reads;
    mutable std::set<u64> m_reported_uninit_pointers;
    mutable std::set<u64> m_reported_uninit_branches;
};

}
