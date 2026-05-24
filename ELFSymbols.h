#pragma once

#include "Types.h"

#include <string>
#include <vector>

namespace LUE {

struct ELFSymbol {
    std::string name;
    u64 value { 0 };
    u64 size { 0 };
};

struct ELFImageInfo {
    u64 min_vaddr { 0 };
    u64 max_vaddr { 0 };
    std::vector<std::pair<u64, u64>> executable_ranges;
    std::vector<ELFSymbol> function_symbols;
};

ELFImageInfo read_elf_image_info(const std::string& path);

}
