#include "SoftMMU.h"

#include <algorithm>
#include <cstring>
#include <iostream>

namespace LUE {

void SoftMMU::sort_regions()
{
    std::sort(m_regions.begin(), m_regions.end(), [](const Region& a, const Region& b) {
        return a.base < b.base;
    });
}

void SoftMMU::ensure_no_overlap(u64 base, u64 size) const
{
    if (size == 0)
        throw EmulatorError("attempted to map zero bytes");
    u64 end = base + size;
    if (end < base)
        throw EmulatorError("mapping overflow");

    for (auto const& region : m_regions) {
        if (base < region.end() && end > region.base)
            throw EmulatorError("mapping " + hex(base) + "-" + hex(end) + " overlaps " + hex(region.base) + "-" + hex(region.end()) + " (" + region.name + ")");
    }
}

void SoftMMU::map_zeroed(u64 base, u64 size, int prot, std::string name)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    Region region;
    region.base = base;
    region.size = size;
    region.prot = prot;
    region.name = std::move(name);
    region.bytes.resize(size);
    m_regions.push_back(std::move(region));
    sort_regions();
}

void SoftMMU::map_bytes(u64 base, u64 size, int prot, const u8* source, size_t source_size, size_t destination_offset, std::string name)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    if (destination_offset > size || source_size > size - destination_offset)
        throw EmulatorError("file mapping copy exceeds destination region");

    Region region;
    region.base = base;
    region.size = size;
    region.prot = prot;
    region.name = std::move(name);
    region.bytes.resize(size);
    if (source_size)
        std::memcpy(region.bytes.data() + destination_offset, source, source_size);
    m_regions.push_back(std::move(region));
    sort_regions();
}

u64 SoftMMU::allocate(u64 size, u64 alignment, int prot, std::string name)
{
    size = page_align_up(size);
    alignment = std::max<u64>(page_size, alignment);

    for (;;) {
        u64 candidate = (m_next_allocation + alignment - 1) & ~(alignment - 1);
        bool collided = false;
        for (auto const& region : m_regions) {
            if (candidate < region.end() && candidate + size > region.base) {
                m_next_allocation = page_align_up(region.end());
                collided = true;
                break;
            }
        }
        if (!collided) {
            map_zeroed(candidate, size, prot, std::move(name));
            m_next_allocation = candidate + size;
            return candidate;
        }
    }
}

void SoftMMU::split_around(u64 base, u64 size)
{
    u64 end = base + size;
    std::vector<Region> rebuilt;
    rebuilt.reserve(m_regions.size() + 4);

    for (auto& region : m_regions) {
        if (end <= region.base || base >= region.end()) {
            rebuilt.push_back(std::move(region));
            continue;
        }

        if (base > region.base) {
            Region left;
            left.base = region.base;
            left.size = base - region.base;
            left.prot = region.prot;
            left.name = region.name;
            left.bytes.assign(region.bytes.begin(), region.bytes.begin() + static_cast<std::ptrdiff_t>(left.size));
            rebuilt.push_back(std::move(left));
        }

        u64 overlap_start = std::max(base, region.base);
        u64 overlap_end = std::min(end, region.end());
        Region middle;
        middle.base = overlap_start;
        middle.size = overlap_end - overlap_start;
        middle.prot = region.prot;
        middle.name = region.name;
        auto middle_begin = region.bytes.begin() + static_cast<std::ptrdiff_t>(overlap_start - region.base);
        middle.bytes.assign(middle_begin, middle_begin + static_cast<std::ptrdiff_t>(middle.size));
        rebuilt.push_back(std::move(middle));

        if (end < region.end()) {
            Region right;
            right.base = end;
            right.size = region.end() - end;
            right.prot = region.prot;
            right.name = region.name;
            auto right_begin = region.bytes.begin() + static_cast<std::ptrdiff_t>(end - region.base);
            right.bytes.assign(right_begin, region.bytes.end());
            rebuilt.push_back(std::move(right));
        }
    }

    m_regions = std::move(rebuilt);
    sort_regions();
}

void SoftMMU::unmap(u64 base, u64 size)
{
    if (size == 0)
        return;
    base = page_align_down(base);
    size = page_align_up(size);
    split_around(base, size);
    u64 end = base + size;
    m_regions.erase(std::remove_if(m_regions.begin(), m_regions.end(), [&](const Region& region) {
        return region.base >= base && region.end() <= end;
    }), m_regions.end());
}

void SoftMMU::protect(u64 base, u64 size, int prot)
{
    if (size == 0)
        return;
    base = page_align_down(base);
    size = page_align_up(size);
    split_around(base, size);
    u64 end = base + size;
    for (auto& region : m_regions) {
        if (region.base >= base && region.end() <= end)
            region.prot = prot;
    }
}

bool SoftMMU::is_mapped(u64 address, size_t size) const
{
    for (size_t i = 0; i < size; ++i) {
        if (!find_region(address + i))
            return false;
    }
    return true;
}

const SoftMMU::Region* SoftMMU::find_region(u64 address) const
{
    for (auto const& region : m_regions) {
        if (region.contains(address))
            return &region;
    }
    return nullptr;
}

SoftMMU::Region* SoftMMU::find_region(u64 address)
{
    for (auto& region : m_regions) {
        if (region.contains(address))
            return &region;
    }
    return nullptr;
}

const SoftMMU::Region& SoftMMU::region_for(u64 address, int required_prot) const
{
    auto* region = find_region(address);
    if (!region)
        throw EmulatorError("unmapped guest memory at " + hex(address));
    if ((region->prot & required_prot) != required_prot)
        throw EmulatorError("guest memory permission fault at " + hex(address) + " in " + region->name);
    return *region;
}

SoftMMU::Region& SoftMMU::region_for(u64 address, int required_prot)
{
    auto* region = find_region(address);
    if (!region)
        throw EmulatorError("unmapped guest memory at " + hex(address));
    if ((region->prot & required_prot) != required_prot)
        throw EmulatorError("guest memory permission fault at " + hex(address) + " in " + region->name);
    return *region;
}

u8 SoftMMU::read8(u64 address) const
{
    auto const& region = region_for(address, ProtRead);
    return region.bytes.at(static_cast<size_t>(address - region.base));
}

u16 SoftMMU::read16(u64 address) const
{
    u16 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u16>(read8(address + i)) << (i * 8);
    return value;
}

u32 SoftMMU::read32(u64 address) const
{
    u32 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u32>(read8(address + i)) << (i * 8);
    return value;
}

u64 SoftMMU::read64(u64 address) const
{
    u64 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u64>(read8(address + i)) << (i * 8);
    return value;
}

void SoftMMU::write8(u64 address, u8 value)
{
    auto& region = region_for(address, ProtWrite);
    region.bytes.at(static_cast<size_t>(address - region.base)) = value;
}

void SoftMMU::write16(u64 address, u16 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

void SoftMMU::write32(u64 address, u32 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

void SoftMMU::write64(u64 address, u64 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

void SoftMMU::copy_from_guest(void* destination, u64 source, size_t size) const
{
    auto* out = static_cast<u8*>(destination);
    for (size_t i = 0; i < size; ++i)
        out[i] = read8(source + i);
}

void SoftMMU::copy_to_guest(u64 destination, const void* source, size_t size)
{
    auto const* in = static_cast<const u8*>(source);
    for (size_t i = 0; i < size; ++i)
        write8(destination + i, in[i]);
}

std::vector<u8> SoftMMU::copy_buffer_from_guest(u64 source, size_t size) const
{
    std::vector<u8> buffer(size);
    copy_from_guest(buffer.data(), source, size);
    return buffer;
}

std::string SoftMMU::read_c_string(u64 address, size_t limit) const
{
    std::string value;
    value.reserve(64);
    for (size_t i = 0; i < limit; ++i) {
        auto ch = read8(address + i);
        if (ch == 0)
            return value;
        value.push_back(static_cast<char>(ch));
    }
    throw EmulatorError("unterminated guest string at " + hex(address));
}

void SoftMMU::dump_regions(std::ostream& stream) const
{
    for (auto const& region : m_regions) {
        stream << hex(region.base, 12) << "-" << hex(region.end(), 12) << " "
               << (region.readable() ? 'r' : '-')
               << (region.writable() ? 'w' : '-')
               << (region.executable() ? 'x' : '-')
               << " " << region.name << "\n";
    }
}

}
