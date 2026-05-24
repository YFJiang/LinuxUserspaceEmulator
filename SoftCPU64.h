#pragma once

#include "SoftMMU.h"

#include <array>
#include <iosfwd>

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
    void set_fs_base(u64 value) { m_fs_base = value; }
    void set_gs_base(u64 value) { m_gs_base = value; }
    u64 fs_base() const { return m_fs_base; }
    u64 gs_base() const { return m_gs_base; }

    void step();
    void dump(std::ostream&) const;
    void trace_current_instruction(std::ostream&) const;
    std::string current_instruction_text() const;

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

    void push64(u64 value);
    u64 pop64();

    u64 mask_for_width(int width) const;
    u64 sign_bit_for_width(int width) const;
    u64 sign_extend(u64 value, int width) const;

    void set_logic_flags(u64 result, int width);
    u64 add(u64 lhs, u64 rhs, int width, bool carry);
    u64 sub(u64 lhs, u64 rhs, int width, bool borrow);
    bool condition(int cc) const;
    void set_flag(u64 flag, bool value);
    bool flag(u64 flag) const;

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

    [[noreturn]] void unsupported(std::string message) const;
    std::string describe_current_instruction() const;

    Emulator& m_emulator;
    SoftMMU& m_mmu;
    std::array<u64, 16> m_gpr {};
    std::array<std::array<u8, 16>, 16> m_xmm {};
    u32 m_mxcsr { 0x1f80 };
    u64 m_rip { 0 };
    u64 m_rflags { 0x202 };
    u64 m_fs_base { 0 };
    u64 m_gs_base { 0 };

    u64 m_instruction_start { 0 };
    u64 m_decode_pc { 0 };
};

}
