#include "SoftCPU64.h"

#include "Emulator.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <sstream>

namespace LUE {
namespace {

static constexpr u64 CF = 1ULL << 0;
static constexpr u64 PF = 1ULL << 2;
static constexpr u64 AF = 1ULL << 4;
static constexpr u64 ZF = 1ULL << 6;
static constexpr u64 SF = 1ULL << 7;
static constexpr u64 DF = 1ULL << 10;
static constexpr u64 OF = 1ULL << 11;

bool parity_even(u8 value)
{
    value ^= value >> 4;
    value &= 0xf;
    return (0x6996 >> value) & 1;
}

const char* register_name(int index)
{
    static constexpr const char* names[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    return names[index & 15];
}

const char* register_name_for_width(int index, int width)
{
    static constexpr const char* names8[] = {
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    };
    static constexpr const char* names16[] = {
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    };
    static constexpr const char* names32[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    };
    if (width == 8)
        return names8[index & 15];
    if (width == 16)
        return names16[index & 15];
    if (width == 32)
        return names32[index & 15];
    return register_name(index);
}

std::string format_hex_bytes(const SoftMMU& mmu, u64 address, size_t count)
{
    std::ostringstream builder;
    for (size_t i = 0; i < count; ++i) {
        if (i)
            builder << ' ';
        builder << hex(mmu.read8(address + i), 2);
    }
    return builder.str();
}

std::string condition_name(int cc)
{
    static constexpr const char* names[] = {
        "o", "no", "b", "ae", "e", "ne", "be", "a",
        "s", "ns", "p", "np", "l", "ge", "le", "g",
    };
    return names[cc & 15];
}

}

SoftCPU64::SoftCPU64(Emulator& emulator)
    : m_emulator(emulator)
    , m_mmu(emulator.mmu())
{
}

u8 SoftCPU64::fetch8()
{
    return m_mmu.read8(m_decode_pc++);
}

u16 SoftCPU64::fetch16()
{
    auto value = m_mmu.read16(m_decode_pc);
    m_decode_pc += 2;
    return value;
}

u32 SoftCPU64::fetch32()
{
    auto value = m_mmu.read32(m_decode_pc);
    m_decode_pc += 4;
    return value;
}

u64 SoftCPU64::fetch64()
{
    auto value = m_mmu.read64(m_decode_pc);
    m_decode_pc += 8;
    return value;
}

SoftCPU64::Prefixes SoftCPU64::read_prefixes()
{
    Prefixes prefixes;
    for (;;) {
        u8 byte = m_mmu.read8(m_decode_pc);
        switch (byte) {
        case 0x66:
            prefixes.operand16 = true;
            ++m_decode_pc;
            break;
        case 0x67:
            prefixes.address32 = true;
            ++m_decode_pc;
            break;
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
            prefixes.segment = byte;
            ++m_decode_pc;
            break;
        case 0xf0:
            prefixes.lock = true;
            ++m_decode_pc;
            break;
        case 0xf2:
            prefixes.repnz = true;
            ++m_decode_pc;
            break;
        case 0xf3:
            prefixes.repz = true;
            ++m_decode_pc;
            break;
        case 0x64:
            prefixes.segment = 64;
            ++m_decode_pc;
            break;
        case 0x65:
            prefixes.segment = 65;
            ++m_decode_pc;
            break;
        default:
            if (byte >= 0x40 && byte <= 0x4f) {
                prefixes.rex_present = true;
                prefixes.rex = byte - 0x40;
                ++m_decode_pc;
                break;
            }
            return prefixes;
        }
    }
}

SoftCPU64::ModRM SoftCPU64::fetch_modrm(const Prefixes& prefixes)
{
    ModRM modrm;
    modrm.byte = fetch8();
    modrm.mod = (modrm.byte >> 6) & 3;
    modrm.reg = ((modrm.byte >> 3) & 7) + prefixes.rex_r();
    modrm.rm = (modrm.byte & 7) + prefixes.rex_b();
    return modrm;
}

SoftCPU64::DecodedAddress SoftCPU64::decode_memory_address(const Prefixes& prefixes, const ModRM& modrm)
{
    int rm_low = modrm.byte & 7;
    i64 displacement = 0;
    u64 base = 0;
    u64 index = 0;
    u64 scale = 1;
    bool has_base = true;
    bool rip_relative = false;

    if (rm_low == 4) {
        u8 sib = fetch8();
        scale = 1ULL << ((sib >> 6) & 3);
        int index_low = (sib >> 3) & 7;
        int base_low = sib & 7;

        if (index_low != 4 || prefixes.rex_x())
            index = reg(index_low + prefixes.rex_x());

        if (modrm.mod == 0 && base_low == 5) {
            has_base = false;
            displacement = fetch_i32();
        } else {
            base = reg(base_low + prefixes.rex_b());
        }
    } else if (modrm.mod == 0 && rm_low == 5) {
        rip_relative = true;
        displacement = fetch_i32();
    } else {
        base = reg(rm_low + prefixes.rex_b());
    }

    if (modrm.mod == 1)
        displacement = fetch_i8();
    else if (modrm.mod == 2)
        displacement = fetch_i32();

    u64 address = 0;
    if (rip_relative)
        address = m_decode_pc + displacement;
    else
        address = (has_base ? base : 0) + index * scale + displacement;

    if (prefixes.address32)
        address &= 0xffffffffULL;
    if (prefixes.segment == 64)
        address += m_fs_base;
    else if (prefixes.segment == 65)
        address += m_gs_base;
    return DecodedAddress { address, rip_relative, displacement };
}

SoftCPU64::Operand SoftCPU64::decode_rm_operand(const Prefixes& prefixes, const ModRM& modrm)
{
    if (modrm.is_register())
        return Operand { true, modrm.rm, 0, false, 0 };
    auto address = decode_memory_address(prefixes, modrm);
    return Operand { false, 0, address.address, address.rip_relative, address.rip_displacement };
}

int SoftCPU64::operand_width(const Prefixes& prefixes) const
{
    if (prefixes.rex_w())
        return 64;
    if (prefixes.operand16)
        return 16;
    return 32;
}

u64 SoftCPU64::mask_for_width(int width) const
{
    if (width == 64)
        return ~0ULL;
    return (1ULL << width) - 1;
}

u64 SoftCPU64::effective_address(const Operand& operand) const
{
    if (!operand.rip_relative)
        return operand.address;
    return m_decode_pc + operand.rip_displacement;
}

u64 SoftCPU64::sign_bit_for_width(int width) const
{
    return 1ULL << (width - 1);
}

u64 SoftCPU64::sign_extend(u64 value, int width) const
{
    u64 sign = sign_bit_for_width(width);
    value &= mask_for_width(width);
    return (value ^ sign) - sign;
}

u64 SoftCPU64::read_gpr(int register_index, int width, const Prefixes& prefixes) const
{
    register_index &= 15;
    if (width == 8) {
        if (!prefixes.rex_present && register_index >= 4 && register_index <= 7)
            return (m_gpr[static_cast<size_t>(register_index - 4)] >> 8) & 0xff;
        return m_gpr[static_cast<size_t>(register_index)] & 0xff;
    }
    if (width == 16)
        return m_gpr[static_cast<size_t>(register_index)] & 0xffff;
    if (width == 32)
        return m_gpr[static_cast<size_t>(register_index)] & 0xffffffffULL;
    return m_gpr[static_cast<size_t>(register_index)];
}

void SoftCPU64::write_gpr(int register_index, int width, u64 value, const Prefixes& prefixes)
{
    register_index &= 15;
    value &= mask_for_width(width);
    auto& target = m_gpr[static_cast<size_t>(register_index)];
    if (width == 8) {
        if (!prefixes.rex_present && register_index >= 4 && register_index <= 7) {
            auto& high_target = m_gpr[static_cast<size_t>(register_index - 4)];
            high_target = (high_target & ~0xff00ULL) | (value << 8);
            return;
        }
        target = (target & ~0xffULL) | value;
        return;
    }
    if (width == 16) {
        target = (target & ~0xffffULL) | value;
        return;
    }
    if (width == 32) {
        target = value;
        return;
    }
    target = value;
}

u64 SoftCPU64::read_operand(const Operand& operand, int width, const Prefixes& prefixes) const
{
    if (operand.is_register)
        return read_gpr(operand.reg, width, prefixes);
    auto address = effective_address(operand);
    if (width == 8)
        return m_mmu.read8(address);
    if (width == 16)
        return m_mmu.read16(address);
    if (width == 32)
        return m_mmu.read32(address);
    return m_mmu.read64(address);
}

void SoftCPU64::write_operand(const Operand& operand, int width, u64 value, const Prefixes& prefixes)
{
    value &= mask_for_width(width);
    if (operand.is_register) {
        write_gpr(operand.reg, width, value, prefixes);
        return;
    }
    auto address = effective_address(operand);
    if (width == 8)
        m_mmu.write8(address, static_cast<u8>(value));
    else if (width == 16)
        m_mmu.write16(address, static_cast<u16>(value));
    else if (width == 32)
        m_mmu.write32(address, static_cast<u32>(value));
    else
        m_mmu.write64(address, value);
}

void SoftCPU64::push64(u64 value)
{
    m_gpr[RSP] -= 8;
    m_mmu.write64(m_gpr[RSP], value);
}

u64 SoftCPU64::pop64()
{
    auto value = m_mmu.read64(m_gpr[RSP]);
    m_gpr[RSP] += 8;
    return value;
}

void SoftCPU64::set_flag(u64 flag_value, bool value)
{
    if (value)
        m_rflags |= flag_value;
    else
        m_rflags &= ~flag_value;
}

bool SoftCPU64::flag(u64 flag_value) const
{
    return (m_rflags & flag_value) != 0;
}

void SoftCPU64::set_logic_flags(u64 result, int width)
{
    result &= mask_for_width(width);
    set_flag(CF, false);
    set_flag(OF, false);
    set_flag(SF, result & sign_bit_for_width(width));
    set_flag(ZF, result == 0);
    set_flag(PF, parity_even(static_cast<u8>(result)));
}

u64 SoftCPU64::add(u64 lhs, u64 rhs, int width, bool carry)
{
    u64 mask = mask_for_width(width);
    u64 carry_value = carry && flag(CF) ? 1 : 0;
    u64 full = (lhs & mask) + (rhs & mask) + carry_value;
    u64 result = full & mask;
    set_flag(CF, full > mask);
    set_flag(AF, ((lhs ^ rhs ^ result) & 0x10) != 0);
    set_flag(SF, result & sign_bit_for_width(width));
    set_flag(ZF, result == 0);
    set_flag(PF, parity_even(static_cast<u8>(result)));
    set_flag(OF, (~(lhs ^ rhs) & (lhs ^ result) & sign_bit_for_width(width)) != 0);
    return result;
}

u64 SoftCPU64::sub(u64 lhs, u64 rhs, int width, bool borrow)
{
    u64 mask = mask_for_width(width);
    u64 borrow_value = borrow && flag(CF) ? 1 : 0;
    u64 rhs_with_borrow = (rhs & mask) + borrow_value;
    u64 result = ((lhs & mask) - rhs_with_borrow) & mask;
    set_flag(CF, (lhs & mask) < rhs_with_borrow);
    set_flag(AF, ((lhs ^ rhs ^ result) & 0x10) != 0);
    set_flag(SF, result & sign_bit_for_width(width));
    set_flag(ZF, result == 0);
    set_flag(PF, parity_even(static_cast<u8>(result)));
    set_flag(OF, ((lhs ^ rhs) & (lhs ^ result) & sign_bit_for_width(width)) != 0);
    return result;
}

bool SoftCPU64::condition(int cc) const
{
    switch (cc & 0xf) {
    case 0x0:
        return flag(OF);
    case 0x1:
        return !flag(OF);
    case 0x2:
        return flag(CF);
    case 0x3:
        return !flag(CF);
    case 0x4:
        return flag(ZF);
    case 0x5:
        return !flag(ZF);
    case 0x6:
        return flag(CF) || flag(ZF);
    case 0x7:
        return !flag(CF) && !flag(ZF);
    case 0x8:
        return flag(SF);
    case 0x9:
        return !flag(SF);
    case 0xa:
        return flag(PF);
    case 0xb:
        return !flag(PF);
    case 0xc:
        return flag(SF) != flag(OF);
    case 0xd:
        return flag(SF) == flag(OF);
    case 0xe:
        return flag(ZF) || (flag(SF) != flag(OF));
    case 0xf:
        return !flag(ZF) && (flag(SF) == flag(OF));
    }
    return false;
}

void SoftCPU64::execute_alu_rm_reg(u8 opcode, const Prefixes& prefixes)
{
    int operation = opcode >> 3;
    int form = opcode & 7;
    int width = (form == 0 || form == 2) ? 8 : operand_width(prefixes);
    auto modrm = fetch_modrm(prefixes);
    auto rm = decode_rm_operand(prefixes, modrm);
    Operand reg_operand { true, modrm.reg, 0 };
    Operand destination = (form == 2 || form == 3) ? reg_operand : rm;
    Operand source = (form == 2 || form == 3) ? rm : reg_operand;

    u64 lhs = read_operand(destination, width, prefixes);
    u64 rhs = read_operand(source, width, prefixes);
    u64 result = 0;

    switch (operation) {
    case 0:
        result = add(lhs, rhs, width, false);
        write_operand(destination, width, result, prefixes);
        break;
    case 1:
        result = (lhs | rhs) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 2:
        result = add(lhs, rhs, width, true);
        write_operand(destination, width, result, prefixes);
        break;
    case 3:
        result = sub(lhs, rhs, width, true);
        write_operand(destination, width, result, prefixes);
        break;
    case 4:
        result = (lhs & rhs) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 5:
        result = sub(lhs, rhs, width, false);
        write_operand(destination, width, result, prefixes);
        break;
    case 6:
        result = (lhs ^ rhs) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 7:
        (void)sub(lhs, rhs, width, false);
        break;
    default:
        unsupported("unknown ALU operation");
    }
}

void SoftCPU64::execute_alu_imm(u8 opcode, const Prefixes& prefixes)
{
    int width = opcode == 0x80 ? 8 : operand_width(prefixes);
    auto modrm = fetch_modrm(prefixes);
    int operation = (modrm.byte >> 3) & 7;
    auto destination = decode_rm_operand(prefixes, modrm);
    u64 imm = 0;
    if (opcode == 0x80)
        imm = fetch8();
    else if (opcode == 0x83)
        imm = sign_extend(fetch8(), 8);
    else if (width == 16)
        imm = fetch16();
    else
        imm = sign_extend(fetch32(), 32);

    u64 lhs = read_operand(destination, width, prefixes);
    u64 result = 0;
    switch (operation) {
    case 0:
        result = add(lhs, imm, width, false);
        write_operand(destination, width, result, prefixes);
        break;
    case 1:
        result = (lhs | imm) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 2:
        result = add(lhs, imm, width, true);
        write_operand(destination, width, result, prefixes);
        break;
    case 3:
        result = sub(lhs, imm, width, true);
        write_operand(destination, width, result, prefixes);
        break;
    case 4:
        result = (lhs & imm) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 5:
        result = sub(lhs, imm, width, false);
        write_operand(destination, width, result, prefixes);
        break;
    case 6:
        result = (lhs ^ imm) & mask_for_width(width);
        set_logic_flags(result, width);
        write_operand(destination, width, result, prefixes);
        break;
    case 7:
        (void)sub(lhs, imm, width, false);
        break;
    }
}

void SoftCPU64::execute_group_ff(const Prefixes& prefixes)
{
    auto modrm = fetch_modrm(prefixes);
    int operation = (modrm.byte >> 3) & 7;
    auto operand = decode_rm_operand(prefixes, modrm);
    if (operation == 0 || operation == 1) {
        int width = operand_width(prefixes);
        auto value = read_operand(operand, width, prefixes);
        auto old_cf = flag(CF);
        auto result = operation == 0 ? add(value, 1, width, false) : sub(value, 1, width, false);
        set_flag(CF, old_cf);
        write_operand(operand, width, result, prefixes);
        return;
    }
    if (operation == 2) {
        auto target = read_operand(operand, 64, prefixes);
        push64(m_decode_pc);
        m_decode_pc = target;
        return;
    }
    if (operation == 4) {
        m_decode_pc = read_operand(operand, 64, prefixes);
        return;
    }
    if (operation == 6) {
        push64(read_operand(operand, 64, prefixes));
        return;
    }
    unsupported("unsupported FF group operation");
}

void SoftCPU64::execute_group_f6_f7(u8 opcode, const Prefixes& prefixes)
{
    int width = opcode == 0xf6 ? 8 : operand_width(prefixes);
    auto modrm = fetch_modrm(prefixes);
    int operation = (modrm.byte >> 3) & 7;
    auto operand = decode_rm_operand(prefixes, modrm);
    switch (operation) {
    case 0: {
        u64 imm = width == 8 ? fetch8() : (width == 16 ? fetch16() : fetch32());
        auto value = read_operand(operand, width, prefixes);
        set_logic_flags(value & imm, width);
        break;
    }
    case 2: {
        auto value = read_operand(operand, width, prefixes);
        write_operand(operand, width, ~value, prefixes);
        break;
    }
    case 3: {
        auto value = read_operand(operand, width, prefixes);
        write_operand(operand, width, sub(0, value, width, false), prefixes);
        break;
    }
    case 4: {
        auto value = read_operand(operand, width, prefixes);
        unsigned __int128 result = static_cast<unsigned __int128>(read_gpr(RAX, width, prefixes)) * static_cast<unsigned __int128>(value);
        if (width == 8) {
            write_gpr(RAX, 16, static_cast<u64>(result), prefixes);
            set_flag(CF, result > 0xff);
            set_flag(OF, result > 0xff);
        } else {
            write_gpr(RAX, width, static_cast<u64>(result), prefixes);
            write_gpr(RDX, width, static_cast<u64>(result >> width), prefixes);
            set_flag(CF, (result >> width) != 0);
            set_flag(OF, (result >> width) != 0);
        }
        break;
    }
    case 5: {
        auto value = read_operand(operand, width, prefixes);
        __int128 lhs = static_cast<__int128>(static_cast<i64>(sign_extend(read_gpr(RAX, width, prefixes), width)));
        __int128 rhs = static_cast<__int128>(static_cast<i64>(sign_extend(value, width)));
        __int128 result = lhs * rhs;
        if (width == 8) {
            write_gpr(RAX, 16, static_cast<u64>(result), prefixes);
            i64 narrowed = static_cast<i64>(sign_extend(static_cast<u64>(result), 8));
            set_flag(CF, result != narrowed);
            set_flag(OF, result != narrowed);
        } else {
            write_gpr(RAX, width, static_cast<u64>(result), prefixes);
            write_gpr(RDX, width, static_cast<u64>(static_cast<unsigned __int128>(result) >> width), prefixes);
            __int128 narrowed = static_cast<__int128>(static_cast<i64>(sign_extend(static_cast<u64>(result), width)));
            set_flag(CF, result != narrowed);
            set_flag(OF, result != narrowed);
        }
        break;
    }
    case 6: {
        auto value = read_operand(operand, width, prefixes);
        if (value == 0)
            throw EmulatorError("guest divide by zero at " + hex(m_instruction_start));
        if (width == 8) {
            u16 dividend = static_cast<u16>(read_gpr(RAX, 16, prefixes));
            u16 quotient = dividend / static_cast<u8>(value);
            u16 remainder = dividend % static_cast<u8>(value);
            if (quotient > 0xff)
                throw EmulatorError("guest divide overflow at " + hex(m_instruction_start));
            write_gpr(RAX, 16, static_cast<u16>((remainder << 8) | quotient), prefixes);
        } else {
            unsigned __int128 dividend = (static_cast<unsigned __int128>(read_gpr(RDX, width, prefixes)) << width) | read_gpr(RAX, width, prefixes);
            unsigned __int128 quotient = dividend / value;
            unsigned __int128 remainder = dividend % value;
            if (quotient > mask_for_width(width))
                throw EmulatorError("guest divide overflow at " + hex(m_instruction_start));
            write_gpr(RAX, width, static_cast<u64>(quotient), prefixes);
            write_gpr(RDX, width, static_cast<u64>(remainder), prefixes);
        }
        break;
    }
    case 7: {
        auto value = read_operand(operand, width, prefixes);
        i64 divisor = static_cast<i64>(sign_extend(value, width));
        if (divisor == 0)
            throw EmulatorError("guest divide by zero at " + hex(m_instruction_start));
        if (width == 8) {
            i16 dividend = static_cast<i16>(read_gpr(RAX, 16, prefixes));
            i16 quotient = dividend / static_cast<i8>(divisor);
            i16 remainder = dividend % static_cast<i8>(divisor);
            if (quotient < -128 || quotient > 127)
                throw EmulatorError("guest divide overflow at " + hex(m_instruction_start));
            write_gpr(RAX, 16, static_cast<u16>((static_cast<u8>(remainder) << 8) | (static_cast<u8>(quotient))), prefixes);
        } else {
            __int128 high = static_cast<__int128>(static_cast<i64>(sign_extend(read_gpr(RDX, width, prefixes), width)));
            __int128 low = static_cast<__int128>(read_gpr(RAX, width, prefixes));
            __int128 dividend = (high << width) | low;
            __int128 quotient = dividend / divisor;
            __int128 remainder = dividend % divisor;
            __int128 min_value = -(__int128(1) << (width - 1));
            __int128 max_value = (__int128(1) << (width - 1)) - 1;
            if (quotient < min_value || quotient > max_value)
                throw EmulatorError("guest divide overflow at " + hex(m_instruction_start));
            write_gpr(RAX, width, static_cast<u64>(quotient), prefixes);
            write_gpr(RDX, width, static_cast<u64>(remainder), prefixes);
        }
        break;
    }
    default:
        unsupported("unsupported F6/F7 group operation");
    }
}

void SoftCPU64::execute_shift_group(u8 opcode, const Prefixes& prefixes)
{
    int width = (opcode == 0xc0 || opcode == 0xd0 || opcode == 0xd2) ? 8 : operand_width(prefixes);
    auto modrm = fetch_modrm(prefixes);
    int operation = (modrm.byte >> 3) & 7;
    auto operand = decode_rm_operand(prefixes, modrm);
    u8 count = 0;
    if (opcode == 0xc0 || opcode == 0xc1)
        count = fetch8() & 0x3f;
    else if (opcode == 0xd0 || opcode == 0xd1)
        count = 1;
    else
        count = static_cast<u8>(m_gpr[RCX]) & 0x3f;
    if (count == 0)
        return;

    u64 value = read_operand(operand, width, prefixes);
    u64 result = value;
    switch (operation) {
    case 0:
        result = ((value << count) | (value >> (width - count))) & mask_for_width(width);
        break;
    case 1:
        result = ((value >> count) | (value << (width - count))) & mask_for_width(width);
        break;
    case 4:
    case 6:
        result = (value << count) & mask_for_width(width);
        break;
    case 5:
        result = (value >> count) & mask_for_width(width);
        break;
    case 7:
        result = sign_extend(value, width) >> count;
        result &= mask_for_width(width);
        break;
    default:
        unsupported("unsupported shift group operation");
    }
    set_logic_flags(result, width);
    write_operand(operand, width, result, prefixes);
}

void SoftCPU64::read_xmm_from_operand(const Operand& operand, std::array<u8, 16>& value, const Prefixes&) const
{
    if (operand.is_register) {
        value = xmm(operand.reg);
        return;
    }
    auto address = effective_address(operand);
    for (size_t i = 0; i < value.size(); ++i)
        value[i] = m_mmu.read8(address + i);
}

void SoftCPU64::write_xmm_to_operand(const Operand& operand, const std::array<u8, 16>& value, const Prefixes&)
{
    if (operand.is_register) {
        xmm(operand.reg) = value;
        return;
    }
    auto address = effective_address(operand);
    for (size_t i = 0; i < value.size(); ++i)
        m_mmu.write8(address + i, value[i]);
}

void SoftCPU64::execute_0f(const Prefixes& prefixes)
{
    u8 opcode = fetch8();

    if (opcode >= 0x80 && opcode <= 0x8f) {
        i32 rel = fetch_i32();
        if (condition(opcode & 0xf))
            m_decode_pc = m_decode_pc + rel;
        return;
    }

    if (opcode >= 0x90 && opcode <= 0x9f) {
        auto modrm = fetch_modrm(prefixes);
        auto operand = decode_rm_operand(prefixes, modrm);
        write_operand(operand, 8, condition(opcode & 0xf) ? 1 : 0, prefixes);
        return;
    }

    if (opcode >= 0x40 && opcode <= 0x4f) {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        int width = operand_width(prefixes);
        if (condition(opcode & 0xf))
            write_gpr(modrm.reg, width, read_operand(source, width, prefixes), prefixes);
        return;
    }

    switch (opcode) {
    case 0x05: {
        u64 next_rip = m_decode_pc;
        m_gpr[RCX] = next_rip;
        m_gpr[R11] = m_rflags;
        m_gpr[RAX] = m_emulator.handle_syscall(m_gpr[RAX]);
        m_decode_pc = next_rip;
        break;
    }
    case 0x1f: {
        auto modrm = fetch_modrm(prefixes);
        if (!modrm.is_register())
            (void)decode_memory_address(prefixes, modrm);
        break;
    }
    case 0x1e:
        // ENDBR64/ENDBR32 when CET is enabled; harmless in the interpreter.
        (void)fetch8();
        break;
    case 0x31: {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        m_gpr[RAX] = static_cast<u32>(now);
        m_gpr[RDX] = static_cast<u32>(static_cast<u64>(now) >> 32);
        break;
    }
    case 0xae: {
        auto modrm = fetch_modrm(prefixes);
        auto operand = decode_rm_operand(prefixes, modrm);
        if (operand.is_register)
            unsupported("unsupported register 0F AE operation");

        auto address = effective_address(operand);
        int operation = (modrm.byte >> 3) & 7;
        if (operation == 0) {
            for (size_t i = 0; i < 512; ++i)
                m_mmu.write8(address + i, 0);
            m_mmu.write32(address + 24, m_mxcsr);
            m_mmu.write32(address + 28, 0xffff);
            for (size_t reg = 0; reg < m_xmm.size(); ++reg) {
                for (size_t byte = 0; byte < 16; ++byte)
                    m_mmu.write8(address + 160 + reg * 16 + byte, m_xmm[reg][byte]);
            }
        } else if (operation == 1) {
            m_mxcsr = m_mmu.read32(address + 24);
            for (size_t reg = 0; reg < m_xmm.size(); ++reg) {
                for (size_t byte = 0; byte < 16; ++byte)
                    m_xmm[reg][byte] = m_mmu.read8(address + 160 + reg * 16 + byte);
            }
        } else if (operation == 2) {
            m_mmu.write32(address, m_mxcsr);
        } else if (operation == 3) {
            m_mxcsr = m_mmu.read32(address);
        } else {
            unsupported("unsupported 0F AE operation");
        }
        break;
    }
    case 0xa2: {
        u32 leaf = static_cast<u32>(m_gpr[RAX]);
        if (leaf == 0) {
            m_gpr[RAX] = 1;
            m_gpr[RBX] = 0x756e6547; // Genu
            m_gpr[RDX] = 0x49656e69; // ineI
            m_gpr[RCX] = 0x6c65746e; // ntel
        } else if (leaf == 1) {
            m_gpr[RAX] = 0x00000663;
            m_gpr[RBX] = 0;
            m_gpr[RCX] = 1u << 0; // SSE3
            m_gpr[RDX] = (1u << 0)  // FPU
                | (1u << 4)         // TSC
                | (1u << 8)         // CX8
                | (1u << 15)        // CMOV
                | (1u << 23)        // MMX
                | (1u << 24)        // FXSR
                | (1u << 25)        // SSE
                | (1u << 26);       // SSE2
        } else if (leaf == 0x80000000U) {
            m_gpr[RAX] = 0x80000001U;
            m_gpr[RBX] = 0;
            m_gpr[RCX] = 0;
            m_gpr[RDX] = 0;
        } else if (leaf == 0x80000001U) {
            m_gpr[RAX] = 0;
            m_gpr[RBX] = 0;
            m_gpr[RCX] = 1u << 0; // LAHF/SAHF in long mode
            m_gpr[RDX] = (1u << 11) // SYSCALL/SYSRET
                | (1u << 20)        // NX
                | (1u << 29);       // Long mode
        } else {
            m_gpr[RAX] = m_gpr[RBX] = m_gpr[RCX] = m_gpr[RDX] = 0;
        }
        break;
    }
    case 0xa3: {
        auto modrm = fetch_modrm(prefixes);
        auto bit_base = decode_rm_operand(prefixes, modrm);
        int width = operand_width(prefixes);
        u64 bit_offset = read_gpr(modrm.reg, width, prefixes);
        u64 value = 0;
        int bit_index = 0;
        if (bit_base.is_register) {
            value = read_operand(bit_base, width, prefixes);
            bit_index = static_cast<int>(bit_offset & (width - 1));
        } else {
            i64 signed_offset = static_cast<i64>(sign_extend(bit_offset, width));
            i64 element_offset = signed_offset / width;
            bit_index = static_cast<int>(signed_offset % width);
            if (bit_index < 0) {
                bit_index += width;
                --element_offset;
            }
            u64 address = effective_address(bit_base) + element_offset * (width / 8);
            value = width == 16 ? m_mmu.read16(address) : (width == 32 ? m_mmu.read32(address) : m_mmu.read64(address));
        }
        set_flag(CF, ((value >> bit_index) & 1) != 0);
        break;
    }
    case 0xaf: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        int width = operand_width(prefixes);
        i64 lhs = static_cast<i64>(sign_extend(read_gpr(modrm.reg, width, prefixes), width));
        i64 rhs = static_cast<i64>(sign_extend(read_operand(source, width, prefixes), width));
        write_gpr(modrm.reg, width, static_cast<u64>(lhs * rhs), prefixes);
        break;
    }
    case 0xb0:
    case 0xb1: {
        int width = opcode == 0xb0 ? 8 : operand_width(prefixes);
        auto modrm = fetch_modrm(prefixes);
        auto destination = decode_rm_operand(prefixes, modrm);
        u64 destination_value = read_operand(destination, width, prefixes);
        u64 accumulator = read_gpr(RAX, width, prefixes);
        if ((destination_value & mask_for_width(width)) == (accumulator & mask_for_width(width))) {
            write_operand(destination, width, read_gpr(modrm.reg, width, prefixes), prefixes);
            set_flag(ZF, true);
        } else {
            write_gpr(RAX, width, destination_value, prefixes);
            set_flag(ZF, false);
        }
        break;
    }
    case 0xb6:
    case 0xb7:
    case 0xbe:
    case 0xbf: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        int source_width = (opcode == 0xb6 || opcode == 0xbe) ? 8 : 16;
        int destination_width = operand_width(prefixes);
        u64 value = read_operand(source, source_width, prefixes);
        if (opcode == 0xbe || opcode == 0xbf)
            value = sign_extend(value, source_width);
        write_gpr(modrm.reg, destination_width, value, prefixes);
        break;
    }
    case 0xbc:
    case 0xbd: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        int width = operand_width(prefixes);
        u64 value = read_operand(source, width, prefixes) & mask_for_width(width);
        if (value == 0) {
            set_flag(ZF, true);
        } else {
            set_flag(ZF, false);
            int index = 0;
            if (opcode == 0xbc) {
                while (((value >> index) & 1) == 0)
                    ++index;
            } else {
                index = width - 1;
                while (((value >> index) & 1) == 0)
                    --index;
            }
            write_gpr(modrm.reg, width, static_cast<u64>(index), prefixes);
        }
        break;
    }
    case 0x10:
    case 0x12:
    case 0x28:
    case 0x6f: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        if (opcode == 0x12 && prefixes.operand16 && !source.is_register) {
            auto& destination = xmm(modrm.reg);
            auto address = effective_address(source);
            for (int i = 0; i < 8; ++i)
                destination[static_cast<size_t>(i)] = m_mmu.read8(address + i);
        } else {
            std::array<u8, 16> value {};
            read_xmm_from_operand(source, value, prefixes);
            xmm(modrm.reg) = value;
        }
        break;
    }
    case 0x6e: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        int width = prefixes.rex_w() ? 64 : 32;
        u64 value = read_operand(source, width, prefixes);
        auto& destination = xmm(modrm.reg);
        destination.fill(0);
        for (int i = 0; i < width / 8; ++i)
            destination[static_cast<size_t>(i)] = static_cast<u8>(value >> (i * 8));
        break;
    }
    case 0x60:
    case 0x61:
    case 0x62: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        auto lhs = xmm(modrm.reg);
        auto& destination = xmm(modrm.reg);
        int element_size = opcode == 0x60 ? 1 : (opcode == 0x61 ? 2 : 4);
        int elements = 8 / element_size;
        for (int lane = 0; lane < elements; ++lane) {
            for (int b = 0; b < element_size; ++b) {
                destination[static_cast<size_t>(lane * element_size * 2 + b)] = lhs[static_cast<size_t>(lane * element_size + b)];
                destination[static_cast<size_t>(lane * element_size * 2 + element_size + b)] = rhs[static_cast<size_t>(lane * element_size + b)];
            }
        }
        break;
    }
    case 0x70: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        u8 selector = fetch8();
        std::array<u8, 16> input {};
        read_xmm_from_operand(source, input, prefixes);
        auto& destination = xmm(modrm.reg);
        for (int lane = 0; lane < 4; ++lane) {
            int source_lane = (selector >> (lane * 2)) & 3;
            for (int b = 0; b < 4; ++b)
                destination[static_cast<size_t>(lane * 4 + b)] = input[static_cast<size_t>(source_lane * 4 + b)];
        }
        break;
    }
    case 0xc6: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        u8 selector = fetch8();
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        auto lhs = xmm(modrm.reg);
        auto& destination = xmm(modrm.reg);
        int lhs_lane = selector & 1;
        int rhs_lane = (selector >> 1) & 1;
        for (int i = 0; i < 8; ++i) {
            destination[static_cast<size_t>(i)] = lhs[static_cast<size_t>(lhs_lane * 8 + i)];
            destination[static_cast<size_t>(8 + i)] = rhs[static_cast<size_t>(rhs_lane * 8 + i)];
        }
        break;
    }
    case 0x74:
    case 0x75:
    case 0x76: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        auto lhs = xmm(modrm.reg);
        auto& destination = xmm(modrm.reg);
        int element_size = opcode == 0x74 ? 1 : (opcode == 0x75 ? 2 : 4);
        for (int offset = 0; offset < 16; offset += element_size) {
            bool equal = true;
            for (int b = 0; b < element_size; ++b)
                equal &= lhs[static_cast<size_t>(offset + b)] == rhs[static_cast<size_t>(offset + b)];
            for (int b = 0; b < element_size; ++b)
                destination[static_cast<size_t>(offset + b)] = equal ? 0xff : 0x00;
        }
        break;
    }
    case 0x73: {
        auto modrm = fetch_modrm(prefixes);
        int operation = (modrm.byte >> 3) & 7;
        auto operand = decode_rm_operand(prefixes, modrm);
        u8 count = fetch8();
        if (!operand.is_register)
            unsupported("SSE byte-shift with memory destination");
        auto& destination = xmm(operand.reg);
        if (operation == 3 || operation == 7) {
            std::array<u8, 16> original = destination;
            destination.fill(0);
            if (count < 16) {
                for (int i = 0; i < 16 - count; ++i) {
                    if (operation == 3)
                        destination[static_cast<size_t>(i)] = original[static_cast<size_t>(i + count)];
                    else
                        destination[static_cast<size_t>(i + count)] = original[static_cast<size_t>(i)];
                }
            }
        } else {
            unsupported("unsupported 0F 73 SSE shift operation");
        }
        break;
    }
    case 0x6c: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        auto lhs = xmm(modrm.reg);
        auto& destination = xmm(modrm.reg);
        for (int i = 0; i < 8; ++i) {
            destination[static_cast<size_t>(i)] = lhs[static_cast<size_t>(i)];
            destination[static_cast<size_t>(8 + i)] = rhs[static_cast<size_t>(i)];
        }
        break;
    }
    case 0x11:
    case 0x29:
    case 0x7f: {
        auto modrm = fetch_modrm(prefixes);
        auto destination = decode_rm_operand(prefixes, modrm);
        write_xmm_to_operand(destination, xmm(modrm.reg), prefixes);
        break;
    }
    case 0x7e: {
        auto modrm = fetch_modrm(prefixes);
        auto operand = decode_rm_operand(prefixes, modrm);
        if (prefixes.repz) {
            u64 value = read_operand(operand, 64, prefixes);
            auto& destination = xmm(modrm.reg);
            destination.fill(0);
            for (int i = 0; i < 8; ++i)
                destination[static_cast<size_t>(i)] = static_cast<u8>(value >> (i * 8));
        } else {
            int width = prefixes.rex_w() ? 64 : 32;
            u64 value = 0;
            for (int i = 0; i < width / 8; ++i)
                value |= static_cast<u64>(xmm(modrm.reg)[static_cast<size_t>(i)]) << (i * 8);
            write_operand(operand, width, value, prefixes);
        }
        break;
    }
    case 0x16: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        auto& destination = xmm(modrm.reg);
        if (source.is_register) {
            auto const& rhs = xmm(source.reg);
            for (int i = 0; i < 8; ++i)
                destination[static_cast<size_t>(8 + i)] = rhs[static_cast<size_t>(i)];
        } else {
            auto address = effective_address(source);
            for (int i = 0; i < 8; ++i)
                destination[static_cast<size_t>(8 + i)] = m_mmu.read8(address + i);
        }
        break;
    }
    case 0xd6: {
        auto modrm = fetch_modrm(prefixes);
        auto destination = decode_rm_operand(prefixes, modrm);
        u64 value = 0;
        for (int i = 0; i < 8; ++i)
            value |= static_cast<u64>(xmm(modrm.reg)[static_cast<size_t>(i)]) << (i * 8);
        write_operand(destination, 64, value, prefixes);
        break;
    }
    case 0xd7: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> input {};
        read_xmm_from_operand(source, input, prefixes);
        u32 mask = 0;
        for (int i = 0; i < 16; ++i) {
            if (input[static_cast<size_t>(i)] & 0x80)
                mask |= 1u << i;
        }
        write_gpr(modrm.reg, 32, mask, prefixes);
        break;
    }
    case 0x57:
    case 0xef: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        for (size_t i = 0; i < rhs.size(); ++i)
            xmm(modrm.reg)[i] ^= rhs[i];
        break;
    }
    case 0xdb:
    case 0xd4:
    case 0xdf:
    case 0xeb: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        for (size_t i = 0; i < rhs.size(); ++i) {
            if (opcode == 0xdb)
                xmm(modrm.reg)[i] &= rhs[i];
            else if (opcode == 0xd4) {
                if (i == 0 || i == 8) {
                    u64 lhs_qword = 0;
                    u64 rhs_qword = 0;
                    for (int b = 0; b < 8; ++b) {
                        lhs_qword |= static_cast<u64>(xmm(modrm.reg)[i + static_cast<size_t>(b)]) << (b * 8);
                        rhs_qword |= static_cast<u64>(rhs[i + static_cast<size_t>(b)]) << (b * 8);
                    }
                    u64 sum = lhs_qword + rhs_qword;
                    for (int b = 0; b < 8; ++b)
                        xmm(modrm.reg)[i + static_cast<size_t>(b)] = static_cast<u8>(sum >> (b * 8));
                }
            }
            else if (opcode == 0xdf)
                xmm(modrm.reg)[i] = static_cast<u8>((~xmm(modrm.reg)[i]) & rhs[i]);
            else
                xmm(modrm.reg)[i] |= rhs[i];
        }
        break;
    }
    case 0xf8:
    case 0xf9:
    case 0xfa: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        std::array<u8, 16> rhs {};
        read_xmm_from_operand(source, rhs, prefixes);
        int element_size = opcode == 0xf8 ? 1 : (opcode == 0xf9 ? 2 : 4);
        auto& destination = xmm(modrm.reg);
        for (int offset = 0; offset < 16; offset += element_size) {
            u64 lhs_value = 0;
            u64 rhs_value = 0;
            for (int b = 0; b < element_size; ++b) {
                lhs_value |= static_cast<u64>(destination[static_cast<size_t>(offset + b)]) << (b * 8);
                rhs_value |= static_cast<u64>(rhs[static_cast<size_t>(offset + b)]) << (b * 8);
            }
            u64 result = (lhs_value - rhs_value) & ((1ULL << (element_size * 8)) - 1);
            for (int b = 0; b < element_size; ++b)
                destination[static_cast<size_t>(offset + b)] = static_cast<u8>(result >> (b * 8));
        }
        break;
    }
    default:
        unsupported("unsupported 0F opcode " + hex(opcode, 2));
    }
}

void SoftCPU64::execute_string_instruction(u8 opcode, const Prefixes& prefixes)
{
    int width = 1;
    if (opcode == 0xa5 || opcode == 0xab)
        width = prefixes.rex_w() ? 8 : (prefixes.operand16 ? 2 : 4);

    u64 count = prefixes.repz ? m_gpr[RCX] : 1;
    i64 step = flag(DF) ? -width : width;
    for (u64 i = 0; i < count; ++i) {
        if (opcode == 0xa4 || opcode == 0xa5) {
            u64 source = m_gpr[RSI];
            if (prefixes.segment == 64)
                source += m_fs_base;
            else if (prefixes.segment == 65)
                source += m_gs_base;
            for (int b = 0; b < width; ++b)
                m_mmu.write8(m_gpr[RDI] + b, m_mmu.read8(source + b));
            m_gpr[RSI] += step;
            m_gpr[RDI] += step;
        } else if (opcode == 0xaa || opcode == 0xab) {
            u64 value = m_gpr[RAX];
            for (int b = 0; b < width; ++b)
                m_mmu.write8(m_gpr[RDI] + b, static_cast<u8>(value >> (b * 8)));
            m_gpr[RDI] += step;
        }
    }
    if (prefixes.repz)
        m_gpr[RCX] = 0;
}

void SoftCPU64::step()
{
    m_instruction_start = m_rip;
    m_decode_pc = m_rip;
    auto prefixes = read_prefixes();
    u8 opcode = fetch8();

    if (opcode <= 0x3d && (opcode & 7) <= 5) {
        int form = opcode & 7;
        if (form <= 3) {
            execute_alu_rm_reg(opcode, prefixes);
            m_rip = m_decode_pc;
            return;
        }

        int operation = opcode >> 3;
        int width = form == 4 ? 8 : operand_width(prefixes);
        u64 lhs = read_gpr(RAX, width, prefixes);
        u64 imm = 0;
        if (form == 4)
            imm = fetch8();
        else if (width == 16)
            imm = fetch16();
        else
            imm = prefixes.rex_w() ? sign_extend(fetch32(), 32) : fetch32();

        u64 result = 0;
        switch (operation) {
        case 0:
            result = add(lhs, imm, width, false);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 1:
            result = lhs | imm;
            set_logic_flags(result, width);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 2:
            result = add(lhs, imm, width, true);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 3:
            result = sub(lhs, imm, width, true);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 4:
            result = lhs & imm;
            set_logic_flags(result, width);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 5:
            result = sub(lhs, imm, width, false);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 6:
            result = lhs ^ imm;
            set_logic_flags(result, width);
            write_gpr(RAX, width, result, prefixes);
            break;
        case 7:
            (void)sub(lhs, imm, width, false);
            break;
        }
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0x70 && opcode <= 0x7f) {
        i8 rel = fetch_i8();
        if (condition(opcode & 0xf))
            m_decode_pc = m_decode_pc + rel;
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0x90 && opcode <= 0x97) {
        int other = (opcode & 7) + prefixes.rex_b();
        if (other != RAX) {
            u64 tmp = m_gpr[RAX];
            m_gpr[RAX] = m_gpr[other];
            m_gpr[other] = tmp;
        }
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0xb0 && opcode <= 0xb7) {
        write_gpr((opcode - 0xb0) + prefixes.rex_b(), 8, fetch8(), prefixes);
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0xb8 && opcode <= 0xbf) {
        int target = (opcode - 0xb8) + prefixes.rex_b();
        if (prefixes.rex_w())
            write_gpr(target, 64, fetch64(), prefixes);
        else if (prefixes.operand16)
            write_gpr(target, 16, fetch16(), prefixes);
        else
            write_gpr(target, 32, fetch32(), prefixes);
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0x50 && opcode <= 0x57) {
        push64(m_gpr[(opcode - 0x50) + prefixes.rex_b()]);
        m_rip = m_decode_pc;
        return;
    }

    if (opcode >= 0x58 && opcode <= 0x5f) {
        m_gpr[(opcode - 0x58) + prefixes.rex_b()] = pop64();
        m_rip = m_decode_pc;
        return;
    }

    switch (opcode) {
    case 0x63: {
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        write_gpr(modrm.reg, operand_width(prefixes), sign_extend(read_operand(source, 32, prefixes), 32), prefixes);
        break;
    }
    case 0x68:
        push64(sign_extend(fetch32(), 32));
        break;
    case 0x6a:
        push64(sign_extend(fetch8(), 8));
        break;
    case 0x80:
    case 0x81:
    case 0x83:
        execute_alu_imm(opcode, prefixes);
        break;
    case 0x84:
    case 0x85: {
        int width = opcode == 0x84 ? 8 : operand_width(prefixes);
        auto modrm = fetch_modrm(prefixes);
        auto rm = decode_rm_operand(prefixes, modrm);
        set_logic_flags(read_operand(rm, width, prefixes) & read_gpr(modrm.reg, width, prefixes), width);
        break;
    }
    case 0x87: {
        auto modrm = fetch_modrm(prefixes);
        auto rm = decode_rm_operand(prefixes, modrm);
        int width = operand_width(prefixes);
        u64 lhs = read_operand(rm, width, prefixes);
        u64 rhs = read_gpr(modrm.reg, width, prefixes);
        write_operand(rm, width, rhs, prefixes);
        write_gpr(modrm.reg, width, lhs, prefixes);
        break;
    }
    case 0x88:
    case 0x89: {
        int width = opcode == 0x88 ? 8 : operand_width(prefixes);
        auto modrm = fetch_modrm(prefixes);
        auto destination = decode_rm_operand(prefixes, modrm);
        write_operand(destination, width, read_gpr(modrm.reg, width, prefixes), prefixes);
        break;
    }
    case 0x8a:
    case 0x8b: {
        int width = opcode == 0x8a ? 8 : operand_width(prefixes);
        auto modrm = fetch_modrm(prefixes);
        auto source = decode_rm_operand(prefixes, modrm);
        write_gpr(modrm.reg, width, read_operand(source, width, prefixes), prefixes);
        break;
    }
    case 0x8d: {
        auto modrm = fetch_modrm(prefixes);
        if (modrm.is_register())
            unsupported("lea with register source");
        auto address = decode_memory_address(prefixes, modrm);
        write_gpr(modrm.reg, operand_width(prefixes), address.address, prefixes);
        break;
    }
    case 0x8f: {
        auto modrm = fetch_modrm(prefixes);
        if (((modrm.byte >> 3) & 7) != 0)
            unsupported("unsupported 8F group operation");
        auto destination = decode_rm_operand(prefixes, modrm);
        write_operand(destination, 64, pop64(), prefixes);
        break;
    }
    case 0x98:
        if (prefixes.rex_w())
            m_gpr[RAX] = sign_extend(static_cast<u32>(m_gpr[RAX]), 32);
        else
            write_gpr(RAX, 32, sign_extend(static_cast<u16>(m_gpr[RAX]), 16), prefixes);
        break;
    case 0x99:
        if (prefixes.rex_w())
            m_gpr[RDX] = (m_gpr[RAX] & (1ULL << 63)) ? ~0ULL : 0;
        else
            write_gpr(RDX, 32, (m_gpr[RAX] & (1U << 31)) ? 0xffffffffU : 0, prefixes);
        break;
    case 0xa4:
    case 0xa5:
    case 0xaa:
    case 0xab:
        execute_string_instruction(opcode, prefixes);
        break;
    case 0xa8:
        set_logic_flags((m_gpr[RAX] & 0xff) & fetch8(), 8);
        break;
    case 0xa9:
        set_logic_flags(read_gpr(RAX, operand_width(prefixes), prefixes) & (prefixes.rex_w() ? sign_extend(fetch32(), 32) : fetch32()), operand_width(prefixes));
        break;
    case 0xc0:
    case 0xc1:
    case 0xd0:
    case 0xd1:
    case 0xd2:
    case 0xd3:
        execute_shift_group(opcode, prefixes);
        break;
    case 0xc2: {
        u16 bytes = fetch16();
        m_decode_pc = pop64() + bytes;
        break;
    }
    case 0xc3:
        m_decode_pc = pop64();
        break;
    case 0xc6:
    case 0xc7: {
        int width = opcode == 0xc6 ? 8 : operand_width(prefixes);
        auto modrm = fetch_modrm(prefixes);
        if (((modrm.byte >> 3) & 7) != 0)
            unsupported("unsupported C6/C7 group operation");
        auto destination = decode_rm_operand(prefixes, modrm);
        u64 value = width == 8 ? fetch8() : (width == 16 ? fetch16() : sign_extend(fetch32(), 32));
        write_operand(destination, width, value, prefixes);
        break;
    }
    case 0xc9:
        m_gpr[RSP] = m_gpr[RBP];
        m_gpr[RBP] = pop64();
        break;
    case 0xe0:
    case 0xe1:
    case 0xe2: {
        i8 rel = fetch_i8();
        --m_gpr[RCX];
        bool take = opcode == 0xe2 ? m_gpr[RCX] != 0 : (opcode == 0xe1 ? m_gpr[RCX] != 0 && flag(ZF) : m_gpr[RCX] != 0 && !flag(ZF));
        if (take)
            m_decode_pc = m_decode_pc + rel;
        break;
    }
    case 0xe3: {
        i8 rel = fetch_i8();
        if (m_gpr[RCX] == 0)
            m_decode_pc = m_decode_pc + rel;
        break;
    }
    case 0xe8: {
        i32 rel = fetch_i32();
        push64(m_decode_pc);
        m_decode_pc = m_decode_pc + rel;
        break;
    }
    case 0xe9:
    {
        i32 rel = fetch_i32();
        m_decode_pc = m_decode_pc + rel;
        break;
    }
    case 0xeb:
    {
        i8 rel = fetch_i8();
        m_decode_pc = m_decode_pc + rel;
        break;
    }
    case 0xf6:
    case 0xf7:
        execute_group_f6_f7(opcode, prefixes);
        break;
    case 0xfc:
        set_flag(DF, false);
        break;
    case 0xfd:
        set_flag(DF, true);
        break;
    case 0xf8:
        set_flag(CF, false);
        break;
    case 0x0f:
        execute_0f(prefixes);
        break;
    case 0xff:
        execute_group_ff(prefixes);
        break;
    default:
        unsupported("unsupported opcode " + hex(opcode, 2));
    }

    m_rip = m_decode_pc;
}

void SoftCPU64::dump(std::ostream& stream) const
{
    stream << "rip=" << hex(m_rip, 12) << " rflags=" << hex(m_rflags) << "\n";
    for (int i = 0; i < 16; ++i) {
        stream << register_name(i) << "=" << hex(m_gpr[static_cast<size_t>(i)], 16) << ((i % 4 == 3) ? '\n' : ' ');
    }
    stream << "fs_base=" << hex(m_fs_base, 16) << " gs_base=" << hex(m_gs_base, 16) << "\n";
}

void SoftCPU64::trace_current_instruction(std::ostream& stream) const
{
    stream << "instruction: " << describe_current_instruction() << "\n";
    dump(stream);
}

std::string SoftCPU64::current_instruction_text() const
{
    return describe_current_instruction();
}

std::string SoftCPU64::describe_current_instruction() const
{
    struct Cursor {
        const SoftMMU& mmu;
        u64 pc;
        u64 start;

        u8 read8() { return mmu.read8(pc++); }
        u16 read16()
        {
            auto value = mmu.read16(pc);
            pc += 2;
            return value;
        }
        u32 read32()
        {
            auto value = mmu.read32(pc);
            pc += 4;
            return value;
        }
        u64 read64()
        {
            auto value = mmu.read64(pc);
            pc += 8;
            return value;
        }
        i8 read_i8() { return static_cast<i8>(read8()); }
        i32 read_i32() { return static_cast<i32>(read32()); }
    };

    struct DecodedModRM {
        u8 byte { 0 };
        int mod { 0 };
        int reg { 0 };
        int rm { 0 };
    };

    auto imm_text = [](i64 value) {
        return std::string("$") + (value < 0 ? "-" + hex(static_cast<u64>(-value)) : hex(static_cast<u64>(value)));
    };

    struct PrefixState {
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

    Cursor cursor { m_mmu, m_rip, m_rip };
    PrefixState prefixes;
    for (;;) {
        u8 byte = m_mmu.read8(cursor.pc);
        switch (byte) {
        case 0x66:
            prefixes.operand16 = true;
            ++cursor.pc;
            continue;
        case 0x67:
            prefixes.address32 = true;
            ++cursor.pc;
            continue;
        case 0xf0:
            prefixes.lock = true;
            ++cursor.pc;
            continue;
        case 0xf2:
            prefixes.repnz = true;
            ++cursor.pc;
            continue;
        case 0xf3:
            prefixes.repz = true;
            ++cursor.pc;
            continue;
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
            prefixes.segment = byte;
            ++cursor.pc;
            continue;
        default:
            if (byte >= 0x40 && byte <= 0x4f) {
                prefixes.rex_present = true;
                prefixes.rex = byte - 0x40;
                ++cursor.pc;
                continue;
            }
            break;
        }
        break;
    }

    auto operand_width = [&]() {
        if (prefixes.rex_w())
            return 64;
        if (prefixes.operand16)
            return 16;
        return 32;
    };

    auto read_modrm = [&]() {
        DecodedModRM modrm;
        modrm.byte = cursor.read8();
        modrm.mod = (modrm.byte >> 6) & 3;
        modrm.reg = ((modrm.byte >> 3) & 7) + prefixes.rex_r();
        modrm.rm = (modrm.byte & 7) + prefixes.rex_b();
        return modrm;
    };

    auto memory_text = [&](const DecodedModRM& modrm, int trailing_bytes = 0) {
        std::ostringstream out;
        int rm_low = modrm.byte & 7;
        i64 displacement = 0;
        bool has_base = true;
        bool rip_relative = false;
        std::string base;
        std::string index;
        int scale = 1;

        if (rm_low == 4) {
            u8 sib = cursor.read8();
            scale = 1 << ((sib >> 6) & 3);
            int index_low = (sib >> 3) & 7;
            int base_low = sib & 7;
            if (index_low != 4)
                index = register_name(index_low + prefixes.rex_x());
            if (modrm.mod == 0 && base_low == 5) {
                has_base = false;
                displacement = cursor.read_i32();
            } else {
                base = register_name(base_low + prefixes.rex_b());
            }
        } else if (modrm.mod == 0 && rm_low == 5) {
            rip_relative = true;
            displacement = cursor.read_i32();
        } else {
            base = register_name(rm_low + prefixes.rex_b());
        }

        if (modrm.mod == 1)
            displacement = cursor.read_i8();
        else if (modrm.mod == 2)
            displacement = cursor.read_i32();

        if (prefixes.segment == 0x64)
            out << "%fs:";
        else if (prefixes.segment == 0x65)
            out << "%gs:";

        if (rip_relative) {
            u64 target = cursor.pc + displacement + trailing_bytes;
            out << hex(target) << "(%rip)";
            return out.str();
        }

        if (!has_base && index.empty()) {
            out << hex(static_cast<u64>(displacement));
            return out.str();
        }

        if (displacement)
            out << (displacement < 0 ? "-" : "") << hex(static_cast<u64>(displacement < 0 ? -displacement : displacement));
        out << "(";
        if (!base.empty())
            out << "%" << base;
        if (!index.empty()) {
            out << ",%" << index;
            if (scale != 1)
                out << "," << scale;
        }
        out << ")";
        return out.str();
    };

    auto rm_text = [&](const DecodedModRM& modrm, int width, int trailing_bytes = 0) {
        if (modrm.mod == 3)
            return std::string("%") + register_name_for_width(modrm.rm, width);
        return memory_text(modrm, trailing_bytes);
    };

    auto reg_text = [&](int reg, int width) {
        return std::string("%") + register_name_for_width(reg, width);
    };

    auto with_prefixes = [&](const std::string& text) {
        std::string result;
        if (prefixes.lock)
            result += "lock ";
        if (prefixes.repz)
            result += "rep ";
        if (prefixes.repnz)
            result += "repnz ";
        result += text;
        result += "    ; bytes: ";
        result += format_hex_bytes(m_mmu, cursor.start, cursor.pc - cursor.start);
        return result;
    };

    u8 opcode = cursor.read8();
    std::ostringstream out;

    if (opcode <= 0x3d && (opcode & 7) <= 5) {
        static constexpr const char* ops[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
        int operation = opcode >> 3;
        int form = opcode & 7;
        int width = (form == 0 || form == 2 || form == 4) ? 8 : operand_width();
        if (form <= 3) {
            auto modrm = read_modrm();
            if (form == 0 || form == 1)
                out << ops[operation] << " " << reg_text(modrm.reg, width) << ", " << rm_text(modrm, width);
            else
                out << ops[operation] << " " << rm_text(modrm, width) << ", " << reg_text(modrm.reg, width);
        } else {
            i64 imm = form == 4 ? cursor.read_i8() : (width == 16 ? cursor.read16() : cursor.read_i32());
            out << ops[operation] << " " << imm_text(imm) << ", " << reg_text(RAX, width);
        }
        return with_prefixes(out.str());
    }

    if (opcode >= 0x50 && opcode <= 0x57) {
        out << "push " << reg_text((opcode - 0x50) + prefixes.rex_b(), 64);
        return with_prefixes(out.str());
    }
    if (opcode >= 0x58 && opcode <= 0x5f) {
        out << "pop " << reg_text((opcode - 0x58) + prefixes.rex_b(), 64);
        return with_prefixes(out.str());
    }
    if (opcode >= 0x70 && opcode <= 0x7f) {
        i8 rel = cursor.read_i8();
        out << "j" << condition_name(opcode & 15) << " " << hex(cursor.pc + rel);
        return with_prefixes(out.str());
    }
    if (opcode >= 0x90 && opcode <= 0x97) {
        if (opcode == 0x90 && !prefixes.rex_b())
            out << "nop";
        else
            out << "xchg " << reg_text(RAX, 64) << ", " << reg_text((opcode & 7) + prefixes.rex_b(), 64);
        return with_prefixes(out.str());
    }
    if (opcode >= 0xb0 && opcode <= 0xb7) {
        out << "mov " << imm_text(cursor.read8()) << ", " << reg_text((opcode - 0xb0) + prefixes.rex_b(), 8);
        return with_prefixes(out.str());
    }
    if (opcode >= 0xb8 && opcode <= 0xbf) {
        int width = prefixes.rex_w() ? 64 : (prefixes.operand16 ? 16 : 32);
        u64 imm = width == 64 ? cursor.read64() : (width == 16 ? cursor.read16() : cursor.read32());
        out << "mov " << imm_text(static_cast<i64>(imm)) << ", " << reg_text((opcode - 0xb8) + prefixes.rex_b(), width);
        return with_prefixes(out.str());
    }

    switch (opcode) {
    case 0x0f: {
        u8 op2 = cursor.read8();
        if (op2 == 0x05) {
            out << "syscall";
            return with_prefixes(out.str());
        }
        if (op2 >= 0x80 && op2 <= 0x8f) {
            i32 rel = cursor.read_i32();
            out << "j" << condition_name(op2 & 15) << " " << hex(cursor.pc + rel);
            return with_prefixes(out.str());
        }
        if (op2 >= 0x90 && op2 <= 0x9f) {
            auto modrm = read_modrm();
            out << "set" << condition_name(op2 & 15) << " " << rm_text(modrm, 8);
            return with_prefixes(out.str());
        }
        if (op2 >= 0x40 && op2 <= 0x4f) {
            auto modrm = read_modrm();
            out << "cmov" << condition_name(op2 & 15) << " " << rm_text(modrm, operand_width()) << ", " << reg_text(modrm.reg, operand_width());
            return with_prefixes(out.str());
        }
        if (op2 == 0x1f) {
            auto modrm = read_modrm();
            if (modrm.mod != 3)
                (void)memory_text(modrm);
            out << "nop";
            return with_prefixes(out.str());
        }
        if (op2 == 0x31) {
            out << "rdtsc";
            return with_prefixes(out.str());
        }
        if (op2 == 0xa2) {
            out << "cpuid";
            return with_prefixes(out.str());
        }
        if (op2 == 0xa3 || op2 == 0xaf || op2 == 0xb0 || op2 == 0xb1 || op2 == 0xbc || op2 == 0xbd || op2 == 0xb6 || op2 == 0xb7 || op2 == 0xbe || op2 == 0xbf) {
            auto modrm = read_modrm();
            const char* name = op2 == 0xa3 ? "bt" : op2 == 0xaf ? "imul" : op2 == 0xb0 || op2 == 0xb1 ? "cmpxchg" : op2 == 0xbc ? "bsf" : op2 == 0xbd ? "bsr" : op2 == 0xb6 || op2 == 0xb7 ? "movzx" : "movsx";
            out << name << " " << rm_text(modrm, operand_width()) << ", " << reg_text(modrm.reg, operand_width());
            return with_prefixes(out.str());
        }
        if (op2 == 0x10 || op2 == 0x11 || op2 == 0x12 || op2 == 0x16 || op2 == 0x28 || op2 == 0x29 || op2 == 0x57 || op2 == 0x6e || op2 == 0x6f || op2 == 0x7e || op2 == 0x7f || op2 == 0xd6 || op2 == 0xd7 || op2 == 0xef || op2 == 0xdb || op2 == 0xdf || op2 == 0xeb || op2 == 0xd4 || op2 == 0xf8 || op2 == 0xf9 || op2 == 0xfa || op2 == 0x60 || op2 == 0x61 || op2 == 0x62 || op2 == 0x6c || op2 == 0x70 || op2 == 0x73 || op2 == 0x74 || op2 == 0x75 || op2 == 0x76 || op2 == 0xc6) {
            auto modrm = read_modrm();
            int trailing_bytes = (op2 == 0x70 || op2 == 0x73 || op2 == 0xc6) ? 1 : 0;
            auto operand = rm_text(modrm, 128, trailing_bytes);
            if (op2 == 0x70 || op2 == 0x73 || op2 == 0xc6)
                (void)cursor.read8();
            const char* name = "sse";
            if (op2 == 0x57 || op2 == 0xef)
                name = "pxor/xorps";
            else if (op2 == 0x74 || op2 == 0x75 || op2 == 0x76)
                name = "pcmpeq";
            else if (op2 == 0xd7)
                name = "pmovmskb";
            else if (op2 == 0xdb)
                name = "pand";
            else if (op2 == 0xeb)
                name = "por";
            else if (op2 == 0xd4)
                name = "paddq";
            else if (op2 == 0xf8 || op2 == 0xf9 || op2 == 0xfa)
                name = "psub";
            else if (op2 == 0xc6)
                name = "shufpd";
            out << name << " " << operand << ", %xmm" << modrm.reg;
            return with_prefixes(out.str());
        }
        out << "0f " << hex(op2, 2);
        return with_prefixes(out.str());
    }
    case 0x63: {
        auto modrm = read_modrm();
        out << "movsxd " << rm_text(modrm, 32) << ", " << reg_text(modrm.reg, operand_width());
        return with_prefixes(out.str());
    }
    case 0x68:
        out << "push " << imm_text(cursor.read_i32());
        return with_prefixes(out.str());
    case 0x6a:
        out << "push " << imm_text(cursor.read_i8());
        return with_prefixes(out.str());
    case 0x80:
    case 0x81:
    case 0x83: {
        auto modrm = read_modrm();
        static constexpr const char* ops[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
        int width = opcode == 0x80 ? 8 : operand_width();
        int imm_size = (opcode == 0x80 || opcode == 0x83) ? 1 : (width == 16 ? 2 : 4);
        auto operand = rm_text(modrm, width, imm_size);
        i64 imm = 0;
        if (opcode == 0x80 || opcode == 0x83)
            imm = cursor.read_i8();
        else
            imm = width == 16 ? cursor.read16() : cursor.read_i32();
        out << ops[(modrm.byte >> 3) & 7] << " " << imm_text(imm) << ", " << operand;
        return with_prefixes(out.str());
    }
    case 0x84:
    case 0x85: {
        auto modrm = read_modrm();
        int width = opcode == 0x84 ? 8 : operand_width();
        out << "test " << reg_text(modrm.reg, width) << ", " << rm_text(modrm, width);
        return with_prefixes(out.str());
    }
    case 0x87: {
        auto modrm = read_modrm();
        out << "xchg " << reg_text(modrm.reg, operand_width()) << ", " << rm_text(modrm, operand_width());
        return with_prefixes(out.str());
    }
    case 0x88:
    case 0x89:
    case 0x8a:
    case 0x8b: {
        auto modrm = read_modrm();
        int width = (opcode == 0x88 || opcode == 0x8a) ? 8 : operand_width();
        if (opcode == 0x88 || opcode == 0x89)
            out << "mov " << reg_text(modrm.reg, width) << ", " << rm_text(modrm, width);
        else
            out << "mov " << rm_text(modrm, width) << ", " << reg_text(modrm.reg, width);
        return with_prefixes(out.str());
    }
    case 0x8d: {
        auto modrm = read_modrm();
        out << "lea " << rm_text(modrm, 64) << ", " << reg_text(modrm.reg, operand_width());
        return with_prefixes(out.str());
    }
    case 0x8f: {
        auto modrm = read_modrm();
        out << "pop " << rm_text(modrm, 64);
        return with_prefixes(out.str());
    }
    case 0x98:
        out << (prefixes.rex_w() ? "cdqe" : "cwde");
        return with_prefixes(out.str());
    case 0x99:
        out << (prefixes.rex_w() ? "cqo" : "cdq");
        return with_prefixes(out.str());
    case 0xa4:
    case 0xa5:
    case 0xaa:
    case 0xab:
        out << (opcode == 0xa4 ? "movsb" : opcode == 0xa5 ? "movs" : opcode == 0xaa ? "stosb" : "stos");
        return with_prefixes(out.str());
    case 0xa8:
        out << "test " << imm_text(cursor.read8()) << ", %al";
        return with_prefixes(out.str());
    case 0xa9:
        out << "test " << imm_text(cursor.read_i32()) << ", " << reg_text(RAX, operand_width());
        return with_prefixes(out.str());
    case 0xc0:
    case 0xc1:
    case 0xd0:
    case 0xd1:
    case 0xd2:
    case 0xd3: {
        auto modrm = read_modrm();
        static constexpr const char* ops[] = { "rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar" };
        int trailing_bytes = (opcode == 0xc0 || opcode == 0xc1) ? 1 : 0;
        auto operand = rm_text(modrm, opcode == 0xc0 || opcode == 0xd0 || opcode == 0xd2 ? 8 : operand_width(), trailing_bytes);
        if (opcode == 0xc0 || opcode == 0xc1)
            (void)cursor.read8();
        out << ops[(modrm.byte >> 3) & 7] << " " << operand;
        return with_prefixes(out.str());
    }
    case 0xc2:
        out << "ret " << imm_text(cursor.read16());
        return with_prefixes(out.str());
    case 0xc3:
        out << "ret";
        return with_prefixes(out.str());
    case 0xc6:
    case 0xc7: {
        auto modrm = read_modrm();
        int width = opcode == 0xc6 ? 8 : operand_width();
        int imm_size = width == 8 ? 1 : (width == 16 ? 2 : 4);
        auto operand = rm_text(modrm, width, imm_size);
        i64 imm = width == 8 ? cursor.read_i8() : (width == 16 ? cursor.read16() : cursor.read_i32());
        out << "mov " << imm_text(imm) << ", " << operand;
        return with_prefixes(out.str());
    }
    case 0xc9:
        out << "leave";
        return with_prefixes(out.str());
    case 0xe0:
    case 0xe1:
    case 0xe2:
    case 0xe3: {
        i8 rel = cursor.read_i8();
        out << (opcode == 0xe0 ? "loopne" : opcode == 0xe1 ? "loope" : opcode == 0xe2 ? "loop" : "jrcxz") << " " << hex(cursor.pc + rel);
        return with_prefixes(out.str());
    }
    case 0xe8: {
        i32 rel = cursor.read_i32();
        out << "call " << hex(cursor.pc + rel);
        return with_prefixes(out.str());
    }
    case 0xe9: {
        i32 rel = cursor.read_i32();
        out << "jmp " << hex(cursor.pc + rel);
        return with_prefixes(out.str());
    }
    case 0xeb: {
        i8 rel = cursor.read_i8();
        out << "jmp " << hex(cursor.pc + rel);
        return with_prefixes(out.str());
    }
    case 0xf6:
    case 0xf7: {
        auto modrm = read_modrm();
        static constexpr const char* ops[] = { "test", "test", "not", "neg", "mul", "imul", "div", "idiv" };
        int operation = (modrm.byte >> 3) & 7;
        int trailing_bytes = operation <= 1 ? (opcode == 0xf6 ? 1 : (operand_width() == 16 ? 2 : 4)) : 0;
        out << ops[operation] << " " << rm_text(modrm, opcode == 0xf6 ? 8 : operand_width(), trailing_bytes);
        return with_prefixes(out.str());
    }
    case 0xfc:
        out << "cld";
        return with_prefixes(out.str());
    case 0xfd:
        out << "std";
        return with_prefixes(out.str());
    case 0xf8:
        out << "clc";
        return with_prefixes(out.str());
    case 0xff: {
        auto modrm = read_modrm();
        static constexpr const char* ops[] = { "inc", "dec", "call", "callf", "jmp", "jmpf", "push", "groupff" };
        out << ops[(modrm.byte >> 3) & 7] << " " << rm_text(modrm, 64);
        return with_prefixes(out.str());
    }
    default:
        out << "db " << hex(opcode, 2);
        return with_prefixes(out.str());
    }
}

[[noreturn]] void SoftCPU64::unsupported(std::string message) const
{
    std::ostringstream builder;
    builder << message << " at " << hex(m_instruction_start, 12) << " bytes:";
    u64 end = std::min<u64>(m_decode_pc, m_instruction_start + 15);
    for (u64 address = m_instruction_start; address < end; ++address)
        builder << " " << hex(m_mmu.read8(address), 2);
    throw EmulatorError(builder.str());
}

}
