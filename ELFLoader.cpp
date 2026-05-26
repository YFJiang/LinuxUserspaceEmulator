#include "ELFLoader.h"

#include "ELFCommon.h"

#include <algorithm>
#include <limits>

namespace LUE {
namespace {

int flags_to_prot(u32 flags)
{
    int prot = 0;
    if (flags & ELF::PF_R)
        prot |= ProtRead;
    if (flags & ELF::PF_W)
        prot |= ProtWrite;
    if (flags & ELF::PF_X)
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
    auto data = ELF::read_file(path, "ELF file");
    if (data.size() < sizeof(ELF::Elf64_Ehdr))
        throw EmulatorError(path + " is too small to be an ELF64 file");

    // Validate the ELF header before using offsets and sizes from the file.
    auto ehdr = ELF::object_at<ELF::Elf64_Ehdr>(data, 0, "ELF object");
    if (ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F')
        throw EmulatorError(path + " is not an ELF file");
    if (ehdr.e_ident[4] != 2)
        throw EmulatorError(path + " is not ELFCLASS64");
    if (ehdr.e_ident[5] != 1)
        throw EmulatorError(path + " is not little-endian ELF");
    if (ehdr.e_machine != ELF::EM_X86_64)
        throw EmulatorError(path + " is not EM_X86_64");
    if (ehdr.e_type != ELF::ET_EXEC && ehdr.e_type != ELF::ET_DYN)
        throw EmulatorError(path + " is neither ET_EXEC nor ET_DYN");
    if (ehdr.e_phentsize != sizeof(ELF::Elf64_Phdr))
        throw EmulatorError(path + " has unsupported program-header entry size");
    if (ehdr.e_phnum == 0)
        throw EmulatorError(path + " has no program headers");
    if (ehdr.e_phoff > data.size() || static_cast<u64>(ehdr.e_phnum) * ehdr.e_phentsize > data.size() - ehdr.e_phoff)
        throw EmulatorError(path + " has invalid program-header table");

    // ET_DYN objects are position independent and get placed at dyn_base.
    u64 load_base = ehdr.e_type == ELF::ET_DYN ? dyn_base : 0;
    LoadedObject object;
    object.load_base = load_base;
    object.entry = load_base + ehdr.e_entry;
    object.phent = ehdr.e_phentsize;
    object.phnum = ehdr.e_phnum;

    // Program headers describe the interpreter, phdr location, and loadable segments.
    for (u16 i = 0; i < ehdr.e_phnum; ++i) {
        auto phdr = ELF::object_at<ELF::Elf64_Phdr>(data, ehdr.e_phoff + static_cast<u64>(i) * ehdr.e_phentsize, "ELF object");
        if (phdr.p_type == ELF::PT_INTERP) {
            if (phdr.p_offset > data.size() || phdr.p_filesz > data.size() - phdr.p_offset)
                throw EmulatorError(path + " has invalid PT_INTERP");
            object.interpreter.assign(reinterpret_cast<const char*>(data.data() + phdr.p_offset), static_cast<size_t>(phdr.p_filesz));
            if (!object.interpreter.empty() && object.interpreter.back() == '\0')
                object.interpreter.pop_back();
            continue;
        }
        if (phdr.p_type == ELF::PT_PHDR) {
            object.phdr = load_base + phdr.p_vaddr;
            continue;
        }
        if (phdr.p_type == ELF::PT_GNU_STACK)
            continue;
        if (phdr.p_type != ELF::PT_LOAD)
            continue;

        if (phdr.p_filesz > phdr.p_memsz)
            throw EmulatorError(path + " has PT_LOAD p_filesz > p_memsz");
        if (phdr.p_offset > data.size() || phdr.p_filesz > data.size() - phdr.p_offset)
            throw EmulatorError(path + " has PT_LOAD outside file");

        // Map the segment on page boundaries while preserving its in-page offset.
        u64 segment_start = load_base + phdr.p_vaddr;
        u64 map_start = page_align_down(segment_start);
        u64 map_offset = segment_start - map_start;
        u64 map_size = page_align_up(map_offset + phdr.p_memsz);
        int prot = flags_to_prot(phdr.p_flags);
        mmu.map_bytes(map_start, map_size, prot, data.data() + phdr.p_offset, static_cast<size_t>(phdr.p_filesz), static_cast<size_t>(map_offset), path);

        object.brk_start = std::max(object.brk_start, page_align_up(segment_start + phdr.p_memsz));

        // If PT_PHDR is absent, infer the phdr address from the segment containing it.
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
    // Load the main executable first; ET_DYN executables use this preferred base.
    auto executable = load_object(mmu, path, executable_dyn_base);

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
        // Dynamic executables start in the interpreter, which later jumps to the program entry.
        auto interpreter = load_object(mmu, executable.interpreter, interpreter_dyn_base);
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
