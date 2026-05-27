#include "SoftMMU.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <utility>

namespace LUE {

// Record the address range, permissions, and display name shared by all regions.
SoftMMU::Region::Region(u64 base, u64 size, int prot, std::string name)
    : base(base)
    , size(size)
    , prot(prot)
    , name(std::move(name))
{
}

// Create an anonymous in-memory region filled with zero bytes.
SoftMMU::SimpleRegion::SimpleRegion(u64 base, u64 size, int prot, std::string name)
    : Region(base, size, prot, std::move(name))
    , m_bytes(size)
    , m_initialized(size, 1)
{
}

// Create an anonymous in-memory region from an existing byte buffer.
SoftMMU::SimpleRegion::SimpleRegion(u64 base, u64 size, int prot, std::string name, std::vector<u8> bytes)
    : Region(base, size, prot, std::move(name))
    , m_bytes(std::move(bytes))
    , m_initialized(size, 1)
{
    if (m_bytes.size() != size)
        throw EmulatorError("simple region byte size mismatch");
}

// Read one byte at a region-relative offset.
u8 SoftMMU::SimpleRegion::read_offset(u64 offset) const
{
    return m_bytes.at(static_cast<size_t>(offset));
}

// Read one byte and carry its initialization shadow state with it.
ValueWithShadow<u8> SoftMMU::SimpleRegion::read_offset_with_shadow(u64 offset) const
{
    auto value = read_offset(offset);
    return is_offset_initialized(offset) ? ValueWithShadow<u8>::initialized(value) : ValueWithShadow<u8>::uninitialized(value);
}

// Write one byte and update whether that byte is considered initialized.
void SoftMMU::SimpleRegion::write_offset(u64 offset, u8 value, bool initialized)
{
    m_bytes.at(static_cast<size_t>(offset)) = value;
    set_offset_initialized(offset, initialized);
}

// Report whether a region-relative byte has initialized data.
bool SoftMMU::SimpleRegion::is_offset_initialized(u64 offset) const
{
    return m_initialized.at(static_cast<size_t>(offset)) != 0;
}

// Set the initialization shadow state for one region-relative byte.
void SoftMMU::SimpleRegion::set_offset_initialized(u64 offset, bool initialized)
{
    m_initialized.at(static_cast<size_t>(offset)) = initialized ? 1 : 0;
}

// Clone a subrange into a standalone anonymous region.
std::unique_ptr<SoftMMU::Region> SoftMMU::SimpleRegion::clone_slice(u64 new_base, u64 offset, u64 new_size) const
{
    // Copy the requested byte range into a new region at new_base.
    auto begin = m_bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    auto end = begin + static_cast<std::ptrdiff_t>(new_size);
    auto clone = std::make_unique<SimpleRegion>(new_base, new_size, prot, name, std::vector<u8>(begin, end));
    // Preserve the per-byte initialization shadow state for the slice.
    auto shadow_begin = m_initialized.begin() + static_cast<std::ptrdiff_t>(offset);
    auto shadow_end = shadow_begin + static_cast<std::ptrdiff_t>(new_size);
    for (u64 i = 0; shadow_begin + static_cast<std::ptrdiff_t>(i) != shadow_end; ++i)
        clone->set_offset_initialized(i, (*(shadow_begin + static_cast<std::ptrdiff_t>(i))) != 0);
    return clone;
}

// Create a mmap-style region that remembers its source path and file offset.
SoftMMU::MmapRegion::MmapRegion(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset)
    : Region(base, size, prot, std::move(name))
    , m_path(std::move(path))
    , m_file_offset(file_offset)
    , m_bytes(size)
    , m_initialized(size, 1)
{
}

// Create a mmap-style region from an existing byte buffer.
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

// Read one byte at a mmap-region-relative offset.
u8 SoftMMU::MmapRegion::read_offset(u64 offset) const
{
    return m_bytes.at(static_cast<size_t>(offset));
}

// Read one mmap byte and carry its initialization shadow state with it.
ValueWithShadow<u8> SoftMMU::MmapRegion::read_offset_with_shadow(u64 offset) const
{
    auto value = read_offset(offset);
    return is_offset_initialized(offset) ? ValueWithShadow<u8>::initialized(value) : ValueWithShadow<u8>::uninitialized(value);
}

// Write one mmap byte and update whether that byte is considered initialized.
void SoftMMU::MmapRegion::write_offset(u64 offset, u8 value, bool initialized)
{
    m_bytes.at(static_cast<size_t>(offset)) = value;
    set_offset_initialized(offset, initialized);
}

// Report whether a mmap-region-relative byte has initialized data.
bool SoftMMU::MmapRegion::is_offset_initialized(u64 offset) const
{
    return m_initialized.at(static_cast<size_t>(offset)) != 0;
}

// Set the initialization shadow state for one mmap-region-relative byte.
void SoftMMU::MmapRegion::set_offset_initialized(u64 offset, bool initialized)
{
    m_initialized.at(static_cast<size_t>(offset)) = initialized ? 1 : 0;
}

// Clone a subrange into a standalone mmap-style region.
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

// Keep the region list ordered by guest base address.
void SoftMMU::sort_regions()
{
    std::sort(m_regions.begin(), m_regions.end(), [](const auto& a, const auto& b) {
        return a->base < b->base;
    });
}

// Validate that a new mapping is non-empty, non-wrapping, and non-overlapping.
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

// Map a page-aligned anonymous region initialized to zero bytes.
void SoftMMU::map_zeroed(u64 base, u64 size, int prot, std::string name)
{
    // Guest mappings are always tracked at page granularity.
    base = page_align_down(base);
    size = page_align_up(size);
    // Refuse overlapping mappings so each guest address has one owner.
    ensure_no_overlap(base, size);
    // SimpleRegion default-initializes its bytes to zero.
    m_regions.push_back(std::make_unique<SimpleRegion>(base, size, prot, std::move(name)));
    sort_regions();
}

// Map a page-aligned anonymous region and copy source bytes into it.
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

// Map a page-aligned mmap-style region with optional file identity metadata.
void SoftMMU::map_mmap(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset)
{
    base = page_align_down(base);
    size = page_align_up(size);
    ensure_no_overlap(base, size);
    m_regions.push_back(std::make_unique<MmapRegion>(base, size, prot, std::move(name), std::move(path), file_offset));
    sort_regions();
}

// Find free guest space and map a zero-filled anonymous allocation there.
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

// Find free guest space and map a mmap-style allocation there.
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

// Split overlapping regions so the target range can be independently modified.
void SoftMMU::split_around(u64 base, u64 size)
{
    u64 end = base + size;
    std::vector<std::unique_ptr<Region>> rebuilt;
    rebuilt.reserve(m_regions.size() + 4);

    for (auto& region : m_regions) {
        // Regions outside the target range can be kept as-is.
        if (end <= region->base || base >= region->end()) {
            rebuilt.push_back(std::move(region));
            continue;
        }

        // Preserve any part before the target range as its own region.
        if (base > region->base) {
            rebuilt.push_back(region->clone_slice(region->base, 0, base - region->base));
        }

        // Make the overlapping part a standalone region for unmap/protect.
        u64 overlap_start = std::max(base, region->base);
        u64 overlap_end = std::min(end, region->end());
        rebuilt.push_back(region->clone_slice(overlap_start, overlap_start - region->base, overlap_end - overlap_start));

        // Preserve any part after the target range as its own region.
        if (end < region->end()) {
            rebuilt.push_back(region->clone_slice(end, end - region->base, region->end() - end));
        }
    }

    m_regions = std::move(rebuilt);
    sort_regions();
}

// Remove any mappings covered by the requested page-aligned range.
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

// Change permissions on mappings covered by the requested page-aligned range.
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

// Check whether every byte in a guest range has a backing region.
bool SoftMMU::is_mapped(u64 address, size_t size) const
{
    for (size_t i = 0; i < size; ++i) {
        if (!find_region(address + i))
            return false;
    }
    return true;
}

// Find the immutable region containing a guest address, if any.
const SoftMMU::Region* SoftMMU::find_region(u64 address) const
{
    for (auto const& region : m_regions) {
        if (region->contains(address))
            return region.get();
    }
    return nullptr;
}

// Find the mutable region containing a guest address, if any.
SoftMMU::Region* SoftMMU::find_region(u64 address)
{
    for (auto& region : m_regions) {
        if (region->contains(address))
            return region.get();
    }
    return nullptr;
}

// Resolve a guest address to an immutable region and enforce permissions.
const SoftMMU::Region& SoftMMU::region_for(u64 address, int required_prot) const
{
    auto* region = find_region(address);
    if (!region)
        throw EmulatorError("unmapped guest memory at " + hex(address));
    if ((region->prot & required_prot) != required_prot)
        throw EmulatorError("guest memory permission fault at " + hex(address) + " in " + region->name);
    return *region;
}

// Resolve a guest address to a mutable region and enforce permissions.
SoftMMU::Region& SoftMMU::region_for(u64 address, int required_prot)
{
    auto* region = find_region(address);
    if (!region)
        throw EmulatorError("unmapped guest memory at " + hex(address));
    if ((region->prot & required_prot) != required_prot)
        throw EmulatorError("guest memory permission fault at " + hex(address) + " in " + region->name);
    return *region;
}

// Read an initialized byte from guest memory.
u8 SoftMMU::read8(u64 address) const
{
    auto value = read8_with_shadow(address);
    if (value.is_uninitialized()) {
        std::cerr << "uninitialized guest memory read at " << hex(address) << "\n";
        throw EmulatorError("uninitialized guest memory read at " + hex(address));
    }
    return value.value();
}

// Read a byte from guest memory while preserving shadow initialization state.
ValueWithShadow<u8> SoftMMU::read8_with_shadow(u64 address) const
{
    auto const& region = region_for(address, ProtRead);
    return region.read_offset_with_shadow(address - region.base);
}

// Read a little-endian 16-bit value from guest memory.
u16 SoftMMU::read16(u64 address) const
{
    u16 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u16>(read8(address + i)) << (i * 8);
    return value;
}

// Read a little-endian 32-bit value from guest memory.
u32 SoftMMU::read32(u64 address) const
{
    u32 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u32>(read8(address + i)) << (i * 8);
    return value;
}

// Read a little-endian 64-bit value from guest memory.
u64 SoftMMU::read64(u64 address) const
{
    u64 value = 0;
    for (size_t i = 0; i < sizeof(value); ++i)
        value |= static_cast<u64>(read8(address + i)) << (i * 8);
    return value;
}

// Write an initialized byte to guest memory.
void SoftMMU::write8(u64 address, u8 value)
{
    write8_with_shadow(address, ValueWithShadow<u8>::initialized(value));
}

// Write a byte to guest memory and preserve the supplied shadow state.
void SoftMMU::write8_with_shadow(u64 address, ValueWithShadow<u8> value)
{
    auto& region = region_for(address, ProtWrite);
    region.write_offset(address - region.base, value.value(), value.is_initialized());
}

// Write a little-endian 16-bit value to guest memory.
void SoftMMU::write16(u64 address, u16 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

// Write a little-endian 32-bit value to guest memory.
void SoftMMU::write32(u64 address, u32 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

// Write a little-endian 64-bit value to guest memory.
void SoftMMU::write64(u64 address, u64 value)
{
    for (size_t i = 0; i < sizeof(value); ++i)
        write8(address + i, static_cast<u8>(value >> (i * 8)));
}

// Mark a guest byte range as initialized or uninitialized.
void SoftMMU::mark_initialized(u64 address, size_t size, bool initialized)
{
    for (size_t i = 0; i < size; ++i) {
        auto& region = region_for(address + i, ProtRead);
        region.set_offset_initialized(address + i - region.base, initialized);
    }
}

// Copy initialized bytes from guest memory into a host buffer.
void SoftMMU::copy_from_guest(void* destination, u64 source, size_t size) const
{
    auto* out = static_cast<u8*>(destination);
    for (size_t i = 0; i < size; ++i)
        out[i] = read8(source + i);
}

// Copy bytes from a host buffer into guest memory.
void SoftMMU::copy_to_guest(u64 destination, const void* source, size_t size)
{
    auto const* in = static_cast<const u8*>(source);
    for (size_t i = 0; i < size; ++i)
        write8(destination + i, in[i]);
}

// Return a host vector containing initialized bytes copied from guest memory.
std::vector<u8> SoftMMU::copy_buffer_from_guest(u64 source, size_t size) const
{
    std::vector<u8> buffer(size);
    copy_from_guest(buffer.data(), source, size);
    return buffer;
}

// Read a NUL-terminated string from guest memory with a maximum length guard.
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

// Print the current guest memory map for diagnostics.
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
