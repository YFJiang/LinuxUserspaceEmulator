#include "SoftMMU.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <utility>

namespace LUE {

SoftMMU::Region::Region(u64 base, u64 size, int prot, std::string name)
    : base(base)
    , size(size)
    , prot(prot)
    , name(std::move(name))
{
}

SoftMMU::SimpleRegion::SimpleRegion(u64 base, u64 size, int prot, std::string name)
    : Region(base, size, prot, std::move(name))
    , m_bytes(size)
    , m_initialized(size, 1)
{
}

SoftMMU::SimpleRegion::SimpleRegion(u64 base, u64 size, int prot, std::string name, std::vector<u8> bytes)
    : Region(base, size, prot, std::move(name))
    , m_bytes(std::move(bytes))
    , m_initialized(size, 1)
{
    if (m_bytes.size() != size)
        throw EmulatorError("simple region byte size mismatch");
}

u8 SoftMMU::SimpleRegion::read_offset(u64 offset) const
{
    return m_bytes.at(static_cast<size_t>(offset));
}

ValueWithShadow<u8> SoftMMU::SimpleRegion::read_offset_with_shadow(u64 offset) const
{
    auto value = read_offset(offset);
    return is_offset_initialized(offset) ? ValueWithShadow<u8>::initialized(value) : ValueWithShadow<u8>::uninitialized(value);
}

void SoftMMU::SimpleRegion::write_offset(u64 offset, u8 value, bool initialized)
{
    m_bytes.at(static_cast<size_t>(offset)) = value;
    set_offset_initialized(offset, initialized);
}

bool SoftMMU::SimpleRegion::is_offset_initialized(u64 offset) const
{
    return m_initialized.at(static_cast<size_t>(offset)) != 0;
}

void SoftMMU::SimpleRegion::set_offset_initialized(u64 offset, bool initialized)
{
    m_initialized.at(static_cast<size_t>(offset)) = initialized ? 1 : 0;
}

std::unique_ptr<SoftMMU::Region> SoftMMU::SimpleRegion::clone_slice(u64 new_base, u64 offset, u64 new_size) const
{
    auto begin = m_bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    auto end = begin + static_cast<std::ptrdiff_t>(new_size);
    auto clone = std::make_unique<SimpleRegion>(new_base, new_size, prot, name, std::vector<u8>(begin, end));
    auto shadow_begin = m_initialized.begin() + static_cast<std::ptrdiff_t>(offset);
    auto shadow_end = shadow_begin + static_cast<std::ptrdiff_t>(new_size);
    for (u64 i = 0; shadow_begin + static_cast<std::ptrdiff_t>(i) != shadow_end; ++i)
        clone->set_offset_initialized(i, (*(shadow_begin + static_cast<std::ptrdiff_t>(i))) != 0);
    return clone;
}

SoftMMU::MmapRegion::MmapRegion(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset)
    : Region(base, size, prot, std::move(name))
    , m_path(std::move(path))
    , m_file_offset(file_offset)
    , m_bytes(size)
    , m_initialized(size, 1)
{
}

SoftMMU::MmapRegion::MmapRegion(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset, std::vector<u8> bytes)
    : Region(base, size, prot, std::move(name))
    , m_path(std::move(path))
    , m_file_offset(file_offset)
    , m_bytes(std::move(bytes))
    , m_initialized(size, 1)
{
    if (m_bytes.size() != size)
        throw EmulatorError("mmap region byte size mismatch");
}

u8 SoftMMU::MmapRegion::read_offset(u64 offset) const
{
    return m_bytes.at(static_cast<size_t>(offset));
}

ValueWithShadow<u8> SoftMMU::MmapRegion::read_offset_with_shadow(u64 offset) const
{
    auto value = read_offset(offset);
    return is_offset_initialized(offset) ? ValueWithShadow<u8>::initialized(value) : ValueWithShadow<u8>::uninitialized(value);
}

void SoftMMU::MmapRegion::write_offset(u64 offset, u8 value, bool initialized)
{
    m_bytes.at(static_cast<size_t>(offset)) = value;
    set_offset_initialized(offset, initialized);
}

bool SoftMMU::MmapRegion::is_offset_initialized(u64 offset) const
{
    return m_initialized.at(static_cast<size_t>(offset)) != 0;
}

void SoftMMU::MmapRegion::set_offset_initialized(u64 offset, bool initialized)
{
    m_initialized.at(static_cast<size_t>(offset)) = initialized ? 1 : 0;
}

std::unique_ptr<SoftMMU::Region> SoftMMU::MmapRegion::clone_slice(u64 new_base, u64 offset, u64 new_size) const
{
    auto begin = m_bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    auto end = begin + static_cast<std::ptrdiff_t>(new_size);
    auto clone = std::make_unique<MmapRegion>(new_base, new_size, prot, name, m_path, m_file_offset + offset, std::vector<u8>(begin, end));
    auto shadow_begin = m_initialized.begin() + static_cast<std::ptrdiff_t>(offset);
    auto shadow_end = shadow_begin + static_cast<std::ptrdiff_t>(new_size);
    for (u64 i = 0; shadow_begin + static_cast<std::ptrdiff_t>(i) != shadow_end; ++i)
        clone->set_offset_initialized(i, (*(shadow_begin + static_cast<std::ptrdiff_t>(i))) != 0);
    return clone;
}

void SoftMMU::sort_regions()
{
    std::sort(m_regions.begin(), m_regions.end(), [](const auto& a, const auto& b) {
        return a->base < b->base;
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
        if (base < region->end() && end > region->base)
            throw EmulatorError("mapping " + hex(base) + "-" + hex(end) + " overlaps " + hex(region->base) + "-" + hex(region->end()) + " (" + region->name + ")");
    }
}

void SoftMMU::map_zeroed(u64 base, u64 size, int prot, std::string name)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    m_regions.push_back(std::make_unique<SimpleRegion>(base, size, prot, std::move(name)));
    sort_regions();
}

void SoftMMU::map_bytes(u64 base, u64 size, int prot, const u8* source, size_t source_size, size_t destination_offset, std::string name)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    if (destination_offset > size || source_size > size - destination_offset)
        throw EmulatorError("file mapping copy exceeds destination region");

    std::vector<u8> bytes(size);
    if (source_size)
        std::memcpy(bytes.data() + destination_offset, source, source_size);
    m_regions.push_back(std::make_unique<SimpleRegion>(base, size, prot, std::move(name), std::move(bytes)));
    sort_regions();
}

void SoftMMU::map_mmap(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    m_regions.push_back(std::make_unique<MmapRegion>(base, size, prot, std::move(name), std::move(path), file_offset));
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
            if (candidate < region->end() && candidate + size > region->base) {
                m_next_allocation = page_align_up(region->end());
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

u64 SoftMMU::allocate_mmap(u64 size, u64 alignment, int prot, std::string name, std::optional<std::string> path, u64 file_offset)
{
    size = page_align_up(size);
    alignment = std::max<u64>(page_size, alignment);

    for (;;) {
        u64 candidate = (m_next_allocation + alignment - 1) & ~(alignment - 1);
        bool collided = false;
        for (auto const& region : m_regions) {
            if (candidate < region->end() && candidate + size > region->base) {
                m_next_allocation = page_align_up(region->end());
                collided = true;
                break;
            }
        }
        if (!collided) {
            map_mmap(candidate, size, prot, std::move(name), std::move(path), file_offset);
            m_next_allocation = candidate + size;
            return candidate;
        }
    }
}

void SoftMMU::split_around(u64 base, u64 size)
{
    u64 end = base + size;
    std::vector<std::unique_ptr<Region>> rebuilt;
    rebuilt.reserve(m_regions.size() + 4);

    for (auto& region : m_regions) {
        if (end <= region->base || base >= region->end()) {
            rebuilt.push_back(std::move(region));
            continue;
        }

        if (base > region->base) {
            rebuilt.push_back(region->clone_slice(region->base, 0, base - region->base));
        }

        u64 overlap_start = std::max(base, region->base);
        u64 overlap_end = std::min(end, region->end());
        rebuilt.push_back(region->clone_slice(overlap_start, overlap_start - region->base, overlap_end - overlap_start));

        if (end < region->end()) {
            rebuilt.push_back(region->clone_slice(end, end - region->base, region->end() - end));
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
    m_regions.erase(std::remove_if(m_regions.begin(), m_regions.end(), [&](const auto& region) {
        return region->base >= base && region->end() <= end;
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
        if (region->base >= base && region->end() <= end)
            region->prot = prot;
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
        if (region->contains(address))
            return region.get();
    }
    return nullptr;
}

SoftMMU::Region* SoftMMU::find_region(u64 address)
{
    for (auto& region : m_regions) {
        if (region->contains(address))
            return region.get();
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
    auto value = read8_with_shadow(address);
    if (value.is_uninitialized()) {
        std::cerr << "uninitialized guest memory read at " << hex(address) << "\n";
        throw EmulatorError("uninitialized guest memory read at " + hex(address));
    }
    return value.value();
}

ValueWithShadow<u8> SoftMMU::read8_with_shadow(u64 address) const
{
    auto const& region = region_for(address, ProtRead);
    return region.read_offset_with_shadow(address - region.base);
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
    write8_with_shadow(address, ValueWithShadow<u8>::initialized(value));
}

void SoftMMU::write8_with_shadow(u64 address, ValueWithShadow<u8> value)
{
    auto& region = region_for(address, ProtWrite);
    region.write_offset(address - region.base, value.value(), value.is_initialized());
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

void SoftMMU::mark_initialized(u64 address, size_t size, bool initialized)
{
    for (size_t i = 0; i < size; ++i) {
        auto& region = region_for(address + i, ProtRead);
        region.set_offset_initialized(address + i - region.base, initialized);
    }
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
        stream << hex(region->base, 12) << "-" << hex(region->end(), 12) << " "
               << (region->readable() ? 'r' : '-')
               << (region->writable() ? 'w' : '-')
               << (region->executable() ? 'x' : '-')
               << " " << region->kind() << " " << region->name << "\n";
    }
}

}
