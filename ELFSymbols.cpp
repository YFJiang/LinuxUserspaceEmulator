#include "ELFSymbols.h"

#include "ELFCommon.h"

#include <algorithm>
#include <limits>

namespace LUE {
namespace {

std::string symbol_name_at(const std::vector<u8>& data, const ELF::Elf64_Shdr& strings, u32 offset)
{
    // Symbol names are offsets into the linked string table.
    if (offset >= strings.sh_size)
        return {};
    u64 start = strings.sh_offset + offset;
    if (start >= data.size())
        return {};
    // Read until the NUL terminator, but never past the string table or file.
    u64 limit = std::min<u64>(data.size(), strings.sh_offset + strings.sh_size);
    std::string name;
    for (u64 i = start; i < limit && data[static_cast<size_t>(i)]; ++i)
        name.push_back(static_cast<char>(data[static_cast<size_t>(i)]));
    // Drop ELF symbol version suffixes such as malloc@@GLIBC_2.2.5.
    auto version = name.find('@');
    if (version != std::string::npos)
        name.resize(version);
    return name;
}

}

ELFImageInfo read_elf_image_info(const std::string& path)
{
    auto data = ELF::read_file(path, "ELF file for symbols");
    if (data.size() < sizeof(ELF::Elf64_Ehdr))
        throw EmulatorError(path + " is too small to be an ELF64 file");

    // Validate the ELF header before trusting any offsets from the file.
    auto ehdr = ELF::object_at<ELF::Elf64_Ehdr>(data, 0, "ELF symbol object");
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
        throw EmulatorError(path + " is not an ELF file");
    if (ehdr.e_ident[4] != 2 || ehdr.e_ident[5] != 1 || ehdr.e_machine != ELF::EM_X86_64)
        throw EmulatorError(path + " is not a supported x86_64 ELF");
    if (ehdr.e_type != ELF::ET_EXEC && ehdr.e_type != ELF::ET_DYN)
        throw EmulatorError(path + " is neither ET_EXEC nor ET_DYN");

    ELFImageInfo info;
    info.min_vaddr = std::numeric_limits<u64>::max();

    // Program headers describe the virtual address ranges loaded at runtime.
    if (ehdr.e_phoff && ehdr.e_phentsize == sizeof(ELF::Elf64_Phdr)
        && ehdr.e_phoff <= data.size()
        && static_cast<u64>(ehdr.e_phnum) * ehdr.e_phentsize <= data.size() - ehdr.e_phoff) {
        for (u16 i = 0; i < ehdr.e_phnum; ++i) {
            auto phdr = ELF::object_at<ELF::Elf64_Phdr>(data, ehdr.e_phoff + static_cast<u64>(i) * ehdr.e_phentsize, "ELF symbol object");
            if (phdr.p_type != ELF::PT_LOAD)
                continue;
            u64 start = page_align_down(phdr.p_vaddr);
            u64 end = page_align_up(phdr.p_vaddr + phdr.p_memsz);
            info.min_vaddr = std::min(info.min_vaddr, start);
            info.max_vaddr = std::max(info.max_vaddr, end);
            if (phdr.p_flags & ELF::PF_X)
                info.executable_ranges.push_back({ start, end });
        }
    }

    if (info.min_vaddr == std::numeric_limits<u64>::max())
        info.min_vaddr = 0;

    // Section headers are optional at runtime, but carry symbol tables when present.
    if (ehdr.e_shoff && ehdr.e_shentsize == sizeof(ELF::Elf64_Shdr)
        && ehdr.e_shoff <= data.size()
        && static_cast<u64>(ehdr.e_shnum) * ehdr.e_shentsize <= data.size() - ehdr.e_shoff) {
        std::vector<ELF::Elf64_Shdr> sections;
        sections.reserve(ehdr.e_shnum);
        for (u16 i = 0; i < ehdr.e_shnum; ++i)
            sections.push_back(ELF::object_at<ELF::Elf64_Shdr>(data, ehdr.e_shoff + static_cast<u64>(i) * ehdr.e_shentsize, "ELF symbol object"));

        for (auto const& section : sections) {
            if (section.sh_type != ELF::SHT_SYMTAB && section.sh_type != ELF::SHT_DYNSYM)
                continue;
            if (section.sh_entsize != sizeof(ELF::Elf64_Sym) || section.sh_link >= sections.size())
                continue;
            if (section.sh_offset > data.size() || section.sh_size > data.size() - section.sh_offset)
                continue;
            auto const& strings = sections[section.sh_link];
            if (strings.sh_offset > data.size() || strings.sh_size > data.size() - strings.sh_offset)
                continue;

            // Keep only named function symbols; these are used for symbolic backtraces.
            u64 count = section.sh_size / section.sh_entsize;
            for (u64 i = 0; i < count; ++i) {
                auto symbol = ELF::object_at<ELF::Elf64_Sym>(data, section.sh_offset + i * section.sh_entsize, "ELF symbol object");
                if ((symbol.st_info & 0xf) != ELF::STT_FUNC || symbol.st_value == 0)
                    continue;
                auto name = symbol_name_at(data, strings, symbol.st_name);
                if (name.empty())
                    continue;
                info.function_symbols.push_back({ std::move(name), symbol.st_value, symbol.st_size });
            }
        }
    }

    // Sort by address so callers can search symbols in code order.
    std::sort(info.function_symbols.begin(), info.function_symbols.end(), [](auto const& a, auto const& b) {
        return a.value < b.value;
    });

    return info;
}

}
