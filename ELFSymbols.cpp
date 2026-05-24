#include "ELFSymbols.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>

namespace LUE {
namespace {

static constexpr u16 ET_EXEC = 2;
static constexpr u16 ET_DYN = 3;
static constexpr u16 EM_X86_64 = 62;

static constexpr u32 PT_LOAD = 1;
static constexpr u32 PF_X = 1;

static constexpr u32 SHT_SYMTAB = 2;
static constexpr u32 SHT_DYNSYM = 11;
static constexpr u8 STT_FUNC = 2;

struct Elf64_Ehdr {
    unsigned char e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

struct Elf64_Phdr {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
};

struct Elf64_Shdr {
    u32 sh_name;
    u32 sh_type;
    u64 sh_flags;
    u64 sh_addr;
    u64 sh_offset;
    u64 sh_size;
    u32 sh_link;
    u32 sh_info;
    u64 sh_addralign;
    u64 sh_entsize;
};

struct Elf64_Sym {
    u32 st_name;
    u8 st_info;
    u8 st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
};

static_assert(sizeof(Elf64_Ehdr) == 64);
static_assert(sizeof(Elf64_Phdr) == 56);
static_assert(sizeof(Elf64_Shdr) == 64);
static_assert(sizeof(Elf64_Sym) == 24);

std::vector<u8> read_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw EmulatorError("failed to open ELF file for symbols: " + path);
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size < 0)
        throw EmulatorError("failed to size ELF file for symbols: " + path);
    file.seekg(0, std::ios::beg);
    std::vector<u8> data(static_cast<size_t>(size));
    if (!data.empty())
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file && !data.empty())
        throw EmulatorError("failed to read ELF file for symbols: " + path);
    return data;
}

template<typename T>
T object_at(const std::vector<u8>& data, u64 offset)
{
    if (offset > data.size() || sizeof(T) > data.size() - static_cast<size_t>(offset))
        throw EmulatorError("ELF symbol object extends past end of file");
    T object {};
    std::memcpy(&object, data.data() + offset, sizeof(T));
    return object;
}

std::string symbol_name_at(const std::vector<u8>& data, const Elf64_Shdr& strings, u32 offset)
{
    if (offset >= strings.sh_size)
        return {};
    u64 start = strings.sh_offset + offset;
    if (start >= data.size())
        return {};
    u64 limit = std::min<u64>(data.size(), strings.sh_offset + strings.sh_size);
    std::string name;
    for (u64 i = start; i < limit && data[static_cast<size_t>(i)]; ++i)
        name.push_back(static_cast<char>(data[static_cast<size_t>(i)]));
    auto version = name.find('@');
    if (version != std::string::npos)
        name.resize(version);
    return name;
}

}

ELFImageInfo read_elf_image_info(const std::string& path)
{
    auto data = read_file(path);
    if (data.size() < sizeof(Elf64_Ehdr))
        throw EmulatorError(path + " is too small to be an ELF64 file");

    auto ehdr = object_at<Elf64_Ehdr>(data, 0);
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
        throw EmulatorError(path + " is not an ELF file");
    if (ehdr.e_ident[4] != 2 || ehdr.e_ident[5] != 1 || ehdr.e_machine != EM_X86_64)
        throw EmulatorError(path + " is not a supported x86_64 ELF");
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
        throw EmulatorError(path + " is neither ET_EXEC nor ET_DYN");

    ELFImageInfo info;
    info.min_vaddr = std::numeric_limits<u64>::max();

    if (ehdr.e_phoff && ehdr.e_phentsize == sizeof(Elf64_Phdr)
        && ehdr.e_phoff <= data.size()
        && static_cast<u64>(ehdr.e_phnum) * ehdr.e_phentsize <= data.size() - ehdr.e_phoff) {
        for (u16 i = 0; i < ehdr.e_phnum; ++i) {
            auto phdr = object_at<Elf64_Phdr>(data, ehdr.e_phoff + static_cast<u64>(i) * ehdr.e_phentsize);
            if (phdr.p_type != PT_LOAD)
                continue;
            u64 start = page_align_down(phdr.p_vaddr);
            u64 end = page_align_up(phdr.p_vaddr + phdr.p_memsz);
            info.min_vaddr = std::min(info.min_vaddr, start);
            info.max_vaddr = std::max(info.max_vaddr, end);
            if (phdr.p_flags & PF_X)
                info.executable_ranges.push_back({ start, end });
        }
    }

    if (info.min_vaddr == std::numeric_limits<u64>::max())
        info.min_vaddr = 0;

    if (ehdr.e_shoff && ehdr.e_shentsize == sizeof(Elf64_Shdr)
        && ehdr.e_shoff <= data.size()
        && static_cast<u64>(ehdr.e_shnum) * ehdr.e_shentsize <= data.size() - ehdr.e_shoff) {
        std::vector<Elf64_Shdr> sections;
        sections.reserve(ehdr.e_shnum);
        for (u16 i = 0; i < ehdr.e_shnum; ++i)
            sections.push_back(object_at<Elf64_Shdr>(data, ehdr.e_shoff + static_cast<u64>(i) * ehdr.e_shentsize));

        for (auto const& section : sections) {
            if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM)
                continue;
            if (section.sh_entsize != sizeof(Elf64_Sym) || section.sh_link >= sections.size())
                continue;
            if (section.sh_offset > data.size() || section.sh_size > data.size() - section.sh_offset)
                continue;
            auto const& strings = sections[section.sh_link];
            if (strings.sh_offset > data.size() || strings.sh_size > data.size() - strings.sh_offset)
                continue;

            u64 count = section.sh_size / section.sh_entsize;
            for (u64 i = 0; i < count; ++i) {
                auto symbol = object_at<Elf64_Sym>(data, section.sh_offset + i * section.sh_entsize);
                if ((symbol.st_info & 0xf) != STT_FUNC || symbol.st_value == 0)
                    continue;
                auto name = symbol_name_at(data, strings, symbol.st_name);
                if (name.empty())
                    continue;
                info.function_symbols.push_back({ std::move(name), symbol.st_value, symbol.st_size });
            }
        }
    }

    std::sort(info.function_symbols.begin(), info.function_symbols.end(), [](auto const& a, auto const& b) {
        return a.value < b.value;
    });

    return info;
}

}
