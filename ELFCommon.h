#pragma once

#include "Types.h"

#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace LUE::ELF {

static constexpr u16 ET_EXEC = 2;
static constexpr u16 ET_DYN = 3;
static constexpr u16 EM_X86_64 = 62;

static constexpr u32 PT_LOAD = 1;
static constexpr u32 PT_INTERP = 3;
static constexpr u32 PT_PHDR = 6;
static constexpr u32 PT_GNU_STACK = 0x6474e551;

static constexpr u32 PF_X = 1;
static constexpr u32 PF_W = 2;
static constexpr u32 PF_R = 4;

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

inline std::vector<u8> read_file(const std::string& path, std::string_view description)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw EmulatorError("failed to open " + std::string(description) + ": " + path);
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size < 0)
        throw EmulatorError("failed to size " + std::string(description) + ": " + path);
    file.seekg(0, std::ios::beg);
    std::vector<u8> data(static_cast<size_t>(size));
    if (!data.empty())
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file && !data.empty())
        throw EmulatorError("failed to read " + std::string(description) + ": " + path);
    return data;
}

template<typename T>
T object_at(const std::vector<u8>& data, u64 offset, std::string_view description)
{
    // Ensure the requested object fits entirely within the file buffer.
    if (offset > data.size() || sizeof(T) > data.size() - static_cast<size_t>(offset))
        throw EmulatorError(std::string(description) + " extends past end of file");
    T object {};
    // Use memcpy so unaligned ELF structures can be read safely.
    std::memcpy(&object, data.data() + offset, sizeof(T));
    return object;
}

}
