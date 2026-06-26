#pragma once

#include "Types.h"

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace LUE {

class Emulator;

class MallocTracer {
public:
    enum class Function {
        None,
        Malloc,
        Free,
        Realloc,
        Calloc,
    };

    struct AllocationRecord {
        u64 ptr { 0 };
        u64 size { 0 };
        std::vector<u64> backtrace;
        bool freed { false };
        // Per-byte "the guest has written this byte" map, used to flag reads of
        // never-initialized heap. Empty means "not tracked" (oversized
        // allocation) and is treated as fully initialized to bound memory use.
        std::vector<bool> initialized;
    };

    static constexpr u64 redzone_size = 16;
    // Allocations larger than this are not byte-tracked for uninitialized reads,
    // so a single huge malloc cannot blow up tracer memory.
    static constexpr u64 max_tracked_init_bytes = 1u << 20;

    explicit MallocTracer(Emulator& emulator);

    bool enabled() const { return m_enabled; }
    void set_enabled(bool enabled) { m_enabled = enabled; }

    void step();
    void on_memory_write(u64 address);
    void on_memory_read(u64 address);

    void dump_leak_report(std::ostream& stream) const;
    void dump_event_log(std::ostream& stream) const;

private:
    Emulator& m_emulator;
    bool m_enabled { false };

    Function m_active_function { Function::None };
    u64 m_entry_args[2] {};
    u64 m_pending_free_ptr { 0 };
    std::vector<u64> m_entry_backtrace;

    std::map<u64, AllocationRecord> m_allocations;
    std::map<u64, AllocationRecord> m_freed;
    std::set<std::string> m_reported_memory_errors;

    Function detect_allocation_function_entry(u64 address) const;
    bool is_in_libc(u64 address) const;
    bool is_internal(u64 address) const;
    bool caller_is_internal() const;

    void on_function_enter(Function function);
    void on_function_leave();

    void on_malloc_leave(u64 result);
    void on_free_enter(u64 ptr);
    void on_free_leave();
    void on_realloc_leave(u64 result);
    void on_calloc_leave(u64 result);

    void record_allocation(u64 ptr, u64 size, bool initialized);
    void move_to_freed(u64 ptr);
    void mark_freed_memory(u64 ptr, u64 size);

    // Fast interval lookups into the live / freed allocation maps.
    AllocationRecord* live_allocation_containing(u64 address);
    const AllocationRecord* freed_allocation_containing(u64 address) const;
    static void mark_byte_initialized(AllocationRecord& record, u64 address);

    // Compute the set of live allocation base addresses reachable from the root
    // set (registers + writable non-heap memory) for the leak report.
    std::set<u64> compute_reachable_allocations() const;

    void report_double_free(u64 ptr, const AllocationRecord& record) const;
    void report_invalid_free(u64 ptr) const;
    void report_realloc_error(const char* message, u64 ptr, const AllocationRecord* record = nullptr) const;
    void report_heap_overflow(u64 address, u64 ptr, const AllocationRecord& record);
    void report_use_after_free(u64 address, u64 ptr, const AllocationRecord& record);
    void report_use_after_free_read(u64 address, u64 ptr, const AllocationRecord& record);
    void report_uninitialized_read(u64 address, u64 ptr, const AllocationRecord& record);

    static const char* function_name(Function function);
};

}
