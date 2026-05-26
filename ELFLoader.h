#pragma once

#include "SoftMMU.h"

#include <string>

namespace LUE {

// Preferred base for ET_DYN main executables, matching the usual Linux PIE area.
static constexpr u64 executable_dyn_base = 0x555555554000ULL;

// Preferred base for the dynamic linker/interpreter, kept in a high shared-library area.
static constexpr u64 interpreter_dyn_base = 0x7f0000000000ULL;

struct LoadedProgram {
    u64 entry { 0 };
    u64 executable_entry { 0 };
    u64 executable_base { 0 };
    u64 interpreter_base { 0 };
    u64 interpreter_phdr { 0 };
    u16 interpreter_phent { 0 };
    u16 interpreter_phnum { 0 };
    u64 phdr { 0 };
    u16 phent { 0 };
    u16 phnum { 0 };
    u64 brk_start { 0 };
    bool dynamic { false };
    std::string executable_path;
    std::string interpreter_path;
};

class ELFLoader {
public:
    static LoadedProgram load(SoftMMU&, const std::string& path);
};

}
