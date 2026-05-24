#pragma once

#include "Types.h"

#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace LUE {

enum MemoryProtection {
    ProtRead = 1,
    ProtWrite = 2,
    ProtExecute = 4,
};

class SoftMMU {
public:
    class Region {
    public:
        Region(u64 base, u64 size, int prot, std::string name);
        virtual ~Region() = default;

        u64 base { 0 };
        u64 size { 0 };
        int prot { 0 };
        std::string name;

        u64 end() const { return base + size; }
        bool contains(u64 address) const { return address >= base && address < end(); }
        bool readable() const { return prot & ProtRead; }
        bool writable() const { return prot & ProtWrite; }
        bool executable() const { return prot & ProtExecute; }

        virtual const char* kind() const = 0;
        virtual u8 read_offset(u64 offset) const = 0;
        virtual void write_offset(u64 offset, u8 value) = 0;
        virtual std::unique_ptr<Region> clone_slice(u64 new_base, u64 offset, u64 new_size) const = 0;
    };

    class SimpleRegion final : public Region {
    public:
        SimpleRegion(u64 base, u64 size, int prot, std::string name);
        SimpleRegion(u64 base, u64 size, int prot, std::string name, std::vector<u8> bytes);

        const char* kind() const override { return "simple"; }
        u8 read_offset(u64 offset) const override;
        void write_offset(u64 offset, u8 value) override;
        std::unique_ptr<Region> clone_slice(u64 new_base, u64 offset, u64 new_size) const override;

    private:
        std::vector<u8> m_bytes;
    };

    class MmapRegion final : public Region {
    public:
        MmapRegion(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset);
        MmapRegion(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path, u64 file_offset, std::vector<u8> bytes);

        const char* kind() const override { return "mmap"; }
        const std::optional<std::string>& path() const { return m_path; }
        u64 file_offset() const { return m_file_offset; }
        u8 read_offset(u64 offset) const override;
        void write_offset(u64 offset, u8 value) override;
        std::unique_ptr<Region> clone_slice(u64 new_base, u64 offset, u64 new_size) const override;

    private:
        std::optional<std::string> m_path;
        u64 m_file_offset { 0 };
        std::vector<u8> m_bytes;
    };

    void map_zeroed(u64 base, u64 size, int prot, std::string name);
    void map_bytes(u64 base, u64 size, int prot, const u8* source, size_t source_size, size_t destination_offset, std::string name);
    void map_mmap(u64 base, u64 size, int prot, std::string name, std::optional<std::string> path = {}, u64 file_offset = 0);
    u64 allocate(u64 size, u64 alignment, int prot, std::string name);
    u64 allocate_mmap(u64 size, u64 alignment, int prot, std::string name, std::optional<std::string> path = {}, u64 file_offset = 0);
    void unmap(u64 base, u64 size);
    void protect(u64 base, u64 size, int prot);

    bool is_mapped(u64 address, size_t size = 1) const;
    const Region* find_region(u64 address) const;
    Region* find_region(u64 address);

    u8 read8(u64 address) const;
    u16 read16(u64 address) const;
    u32 read32(u64 address) const;
    u64 read64(u64 address) const;
    void write8(u64 address, u8 value);
    void write16(u64 address, u16 value);
    void write32(u64 address, u32 value);
    void write64(u64 address, u64 value);

    void copy_from_guest(void* destination, u64 source, size_t size) const;
    void copy_to_guest(u64 destination, const void* source, size_t size);
    std::vector<u8> copy_buffer_from_guest(u64 source, size_t size) const;
    std::string read_c_string(u64 address, size_t limit = 1024 * 1024) const;

    void dump_regions(std::ostream&) const;

private:
    Region& region_for(u64 address, int required_prot);
    const Region& region_for(u64 address, int required_prot) const;
    void ensure_no_overlap(u64 base, u64 size) const;
    void split_around(u64 base, u64 size);
    void sort_regions();

    std::vector<std::unique_ptr<Region>> m_regions;
    u64 m_next_allocation { 0x700000000000ULL };
};

}
