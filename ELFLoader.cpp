#include "ELFLoader.h"

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
static constexpr u32 PT_INTERP = 3;
static constexpr u32 PT_PHDR = 6;
static constexpr u32 PT_GNU_STACK = 0x6474e551;

static constexpr u32 PF_X = 1;
static constexpr u32 PF_W = 2;
static constexpr u32 PF_R = 4;

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

static_assert(sizeof(Elf64_Ehdr) == 64);
static_assert(sizeof(Elf64_Phdr) == 56);

std::vector<u8> read_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw EmulatorError("failed to open ELF file: " + path);
    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    if (size < 0)
        throw EmulatorError("failed to size ELF file: " + path);
    file.seekg(0, std::ios::beg);
    std::vector<u8> data(static_cast<size_t>(size));
    if (!data.empty())
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file && !data.empty())
        throw EmulatorError("failed to read ELF file: " + path);
    return data;
}

template<typename T>
T object_at(const std::vector<u8>& data, u64 offset)
{
    if (offset > data.size() || sizeof(T) > data.size() - static_cast<size_t>(offset))
        throw EmulatorError("ELF object extends past end of file");
    T object {};
    std::memcpy(&object, data.data() + offset, sizeof(T));
    return object;
}

int flags_to_prot(u32 flags)
{
    int prot = 0;
    if (flags & PF_R)
        prot |= ProtRead;
    if (flags & PF_W)
        prot |= ProtWrite;
    if (flags & PF_X)
        prot |= ProtExecute;
    return prot;
}

struct LoadedObject {
    u64 entry { 0 };
    u64 load_base { 0 };
    u64 phdr { 0 };
    u16 phent { 0 };
    u16 phnum { 0 };
    u64 brk_start { 0 };
    std::string interpreter;
};

LoadedObject load_object(SoftMMU& mmu, const std::string& path, u64 dyn_base)
{
    auto data = read_file(path);
    if (data.size() < sizeof(Elf64_Ehdr))
        throw EmulatorError(path + " is too small to be an ELF64 file");

    auto ehdr = object_at<Elf64_Ehdr>(data, 0);
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
        throw EmulatorError(path + " is not an ELF file");
    if (ehdr.e_ident[4] != 2)
        throw EmulatorError(path + " is not ELFCLASS64");
    if (ehdr.e_ident[5] != 1)
        throw EmulatorError(path + " is not little-endian ELF");
    if (ehdr.e_machine != EM_X86_64)
        throw EmulatorError(path + " is not EM_X86_64");
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
        throw EmulatorError(path + " is neither ET_EXEC nor ET_DYN");
    if (ehdr.e_phentsize != sizeof(Elf64_Phdr))
        throw EmulatorError(path + " has unsupported program-header entry size");
    if (ehdr.e_phnum == 0)
        throw EmulatorError(path + " has no program headers");
    if (ehdr.e_phoff > data.size() || static_cast<u64>(ehdr.e_phnum) * ehdr.e_phentsize > data.size() - ehdr.e_phoff)
        throw EmulatorError(path + " has invalid program-header table");

    u64 load_base = ehdr.e_type == ET_DYN ? dyn_base : 0;
    LoadedObject object;
    object.load_base = load_base;
    object.entry = load_base + ehdr.e_entry;
    object.phent = ehdr.e_phentsize;
    object.phnum = ehdr.e_phnum;

    for (u16 i = 0; i < ehdr.e_phnum; ++i) {
        auto phdr = object_at<Elf64_Phdr>(data, ehdr.e_phoff + static_cast<u64>(i) * ehdr.e_phentsize);
        if (phdr.p_type == PT_INTERP) {
            if (phdr.p_offset > data.size() || phdr.p_filesz > data.size() - phdr.p_offset)
                throw EmulatorError(path + " has invalid PT_INTERP");
            object.interpreter.assign(reinterpret_cast<const char*>(data.data() + phdr.p_offset), static_cast<size_t>(phdr.p_filesz));
            if (!object.interpreter.empty() && object.interpreter.back() == '\0')
                object.interpreter.pop_back();
            continue;
        }
        if (phdr.p_type == PT_PHDR) {
            object.phdr = load_base + phdr.p_vaddr;
            continue;
        }
        if (phdr.p_type == PT_GNU_STACK)
            continue;
        if (phdr.p_type != PT_LOAD)
            continue;

        if (phdr.p_filesz > phdr.p_memsz)
            throw EmulatorError(path + " has PT_LOAD p_filesz > p_memsz");
        if (phdr.p_offset > data.size() || phdr.p_filesz > data.size() - phdr.p_offset)
            throw EmulatorError(path + " has PT_LOAD outside file");

        u64 segment_start = load_base + phdr.p_vaddr;
        u64 map_start = page_align_down(segment_start);
        u64 map_offset = segment_start - map_start;
        u64 map_size = page_align_up(map_offset + phdr.p_memsz);
        int prot = flags_to_prot(phdr.p_flags);
        mmu.map_bytes(map_start, map_size, prot, data.data() + phdr.p_offset, static_cast<size_t>(phdr.p_filesz), static_cast<size_t>(map_offset), path);

        object.brk_start = std::max(object.brk_start, page_align_up(segment_start + phdr.p_memsz));

        if (!object.phdr && ehdr.e_phoff >= phdr.p_offset && ehdr.e_phoff < phdr.p_offset + phdr.p_filesz)
            object.phdr = segment_start + (ehdr.e_phoff - phdr.p_offset);
    }

    if (!object.phdr)
        object.phdr = load_base + ehdr.e_phoff;
    if (!object.brk_start)
        throw EmulatorError(path + " did not map any PT_LOAD segments");
    return object;
}

}

LoadedProgram ELFLoader::load(SoftMMU& mmu, const std::string& path)
{
    auto executable = load_object(mmu, path, 0x555555554000ULL);

    LoadedProgram program;
    program.entry = executable.entry;
    program.executable_entry = executable.entry;
    program.executable_base = executable.load_base;
    program.phdr = executable.phdr;
    program.phent = executable.phent;
    program.phnum = executable.phnum;
    program.brk_start = executable.brk_start;
    program.executable_path = path;
    program.interpreter_path = executable.interpreter;

    if (!executable.interpreter.empty()) {
        auto interpreter = load_object(mmu, executable.interpreter, 0x7f0000000000ULL);
        program.dynamic = true;
        program.entry = interpreter.entry;
        program.interpreter_base = interpreter.load_base;
        program.interpreter_phdr = interpreter.phdr;
        program.interpreter_phent = interpreter.phent;
        program.interpreter_phnum = interpreter.phnum;
    }

    return program;
}

}
