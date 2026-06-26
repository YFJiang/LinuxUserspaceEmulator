#include "MallocTracer.h"

#include "Emulator.h"
#include "SoftCPU64.h"
#include "SoftMMU.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <vector>

namespace LUE {

MallocTracer::MallocTracer(Emulator& emulator)
    : m_emulator(emulator)
{
}

void MallocTracer::step()
{
    if (!m_enabled)
        return;

    u64 rip = m_emulator.cpu().rip();
    Function current = detect_allocation_function_entry(rip);

    if (m_active_function == Function::None) {
        // Only track allocations the guest itself requested. Calls made by the
        // dynamic loader (e.g. malloc during lazy PLT resolution) or by libc
        // internals have an internal return address and are ignored, so the
        // first guest malloc is not shadowed by a loader allocation.
        if (current != Function::None && !caller_is_internal()) {
            m_active_function = current;
            on_function_enter(current);
        }
        return;
    }

    if (!is_internal(rip) && current == Function::None) {
        on_function_leave();
        m_active_function = Function::None;
    }
}

void MallocTracer::on_function_enter(Function function)
{
    m_entry_backtrace = m_emulator.raw_backtrace();
    m_entry_args[0] = m_emulator.cpu().reg(SoftCPU64::RDI);
    m_entry_args[1] = m_emulator.cpu().reg(SoftCPU64::RSI);

    if (function == Function::Free)
        on_free_enter(m_entry_args[0]);
}

void MallocTracer::on_function_leave()
{
    u64 result = m_emulator.cpu().reg(SoftCPU64::RAX);

    switch (m_active_function) {
    case Function::Malloc:
        on_malloc_leave(result);
        break;
    case Function::Free:
        on_free_leave();
        break;
    case Function::Realloc:
        on_realloc_leave(result);
        break;
    case Function::Calloc:
        on_calloc_leave(result);
        break;
    case Function::None:
        break;
    }
}

void MallocTracer::on_malloc_leave(u64 result)
{
    if (result == 0)
        return;

    // malloc returns uninitialized storage: track every byte as not-yet-written.
    record_allocation(result, m_entry_args[0], false);

    if (m_emulator.options().trace_syscalls)
        std::cerr << "malloc-tracer: malloc(" << m_entry_args[0] << ") = " << hex(result) << "\n";
}

void MallocTracer::on_free_enter(u64 ptr)
{
    m_pending_free_ptr = 0;
    if (ptr == 0)
        return;

    auto freed_it = m_freed.find(ptr);
    if (freed_it != m_freed.end()) {
        report_double_free(ptr, freed_it->second);
        return;
    }

    auto it = m_allocations.find(ptr);
    if (it == m_allocations.end()) {
        report_invalid_free(ptr);
        return;
    }

    m_pending_free_ptr = ptr;
}

void MallocTracer::on_free_leave()
{
    if (m_pending_free_ptr == 0)
        return;

    move_to_freed(m_pending_free_ptr);
    m_pending_free_ptr = 0;
}

void MallocTracer::on_realloc_leave(u64 result)
{
    u64 old_ptr = m_entry_args[0];
    u64 new_size = m_entry_args[1];

    if (old_ptr == 0) {
        if (result != 0)
            record_allocation(result, new_size, false);
        return;
    }

    if (new_size == 0) {
        if (m_allocations.contains(old_ptr))
            move_to_freed(old_ptr);
        return;
    }

    u64 old_size = 0;
    auto it = m_allocations.find(old_ptr);
    if (it != m_allocations.end()) {
        old_size = it->second.size;
        move_to_freed(old_ptr);
    } else {
        auto freed_it = m_freed.find(old_ptr);
        if (freed_it != m_freed.end())
            report_realloc_error("realloc of freed pointer", old_ptr, &freed_it->second);
        else
            report_realloc_error("realloc of unknown pointer", old_ptr);
    }

    if (result != 0) {
        // realloc preserves the old contents up to min(old, new); the grown tail
        // is fresh and uninitialized.
        record_allocation(result, new_size, false);
        u64 preserved = std::min(old_size, new_size);
        if (auto* record = live_allocation_containing(result)) {
            for (u64 i = 0; i < preserved; ++i)
                mark_byte_initialized(*record, result + i);
        }
    }

    if (m_emulator.options().trace_syscalls)
        std::cerr << "malloc-tracer: realloc(" << hex(old_ptr) << ", " << new_size << ") = " << hex(result) << "\n";
}

void MallocTracer::on_calloc_leave(u64 result)
{
    if (result == 0)
        return;

    u64 nmemb = m_entry_args[0];
    u64 elem_size = m_entry_args[1];
    u64 total = nmemb * elem_size;
    // calloc returns zero-filled storage, so every byte is already initialized.
    record_allocation(result, total, true);

    if (m_emulator.options().trace_syscalls)
        std::cerr << "malloc-tracer: calloc(" << nmemb << ", " << elem_size << ") = " << hex(result) << "\n";
}

void MallocTracer::record_allocation(u64 ptr, u64 size, bool initialized)
{
    AllocationRecord record;
    record.ptr = ptr;
    record.size = size;
    record.backtrace = m_entry_backtrace;
    record.freed = false;
    // Track per-byte write state for the uninitialized-read audit, unless the
    // allocation is too large to track cheaply (then leave the map empty, which
    // is treated as "fully initialized" so it never produces false positives).
    if (size <= max_tracked_init_bytes)
        record.initialized.assign(static_cast<size_t>(size), initialized);

    m_allocations[ptr] = std::move(record);
    m_freed.erase(ptr);

    // Keep the SoftMMU shadow marked initialized for heap memory so the CPU-level
    // taint reporter stays quiet; the uninitialized-read audit is driven entirely
    // by the per-allocation bitmap above.
    try {
        m_emulator.mmu().mark_initialized(ptr, static_cast<size_t>(size), true);
    } catch (const EmulatorError&) {
    }
}

MallocTracer::AllocationRecord* MallocTracer::live_allocation_containing(u64 address)
{
    if (m_allocations.empty())
        return nullptr;
    auto it = m_allocations.upper_bound(address);
    if (it == m_allocations.begin())
        return nullptr;
    --it;
    if (address >= it->first && address < it->first + it->second.size)
        return &it->second;
    return nullptr;
}

const MallocTracer::AllocationRecord* MallocTracer::freed_allocation_containing(u64 address) const
{
    if (m_freed.empty())
        return nullptr;
    auto it = m_freed.upper_bound(address);
    if (it == m_freed.begin())
        return nullptr;
    --it;
    if (address >= it->first && address < it->first + it->second.size)
        return &it->second;
    return nullptr;
}

void MallocTracer::mark_byte_initialized(AllocationRecord& record, u64 address)
{
    if (record.initialized.empty())
        return;
    u64 offset = address - record.ptr;
    if (offset < record.initialized.size())
        record.initialized[static_cast<size_t>(offset)] = true;
}

void MallocTracer::move_to_freed(u64 ptr)
{
    auto it = m_allocations.find(ptr);
    if (it == m_allocations.end())
        return;

    AllocationRecord record = it->second;
    record.freed = true;
    m_allocations.erase(it);
    m_freed[ptr] = record;
    mark_freed_memory(ptr, record.size);

    if (m_emulator.options().trace_syscalls)
        std::cerr << "malloc-tracer: free(" << hex(ptr) << ")\n";
}

void MallocTracer::mark_freed_memory(u64 ptr, u64 size)
{
    (void)ptr;
    (void)size;
}

void MallocTracer::on_memory_write(u64 address)
{
    if (!m_enabled)
        return;

    // Record the write into the per-byte initialization map even when it comes
    // from inside libc (e.g. memcpy/memset into a user buffer), so a later guest
    // read of those bytes is not wrongly flagged as uninitialized.
    if (auto* record = live_allocation_containing(address))
        mark_byte_initialized(*record, address);

    // Only diagnose guest-visible errors from guest code, not from the allocator
    // or other libc/loader internals.
    if (m_active_function != Function::None || is_internal(m_emulator.cpu().rip()))
        return;

    if (auto const* freed = freed_allocation_containing(address)) {
        report_use_after_free(address, freed->ptr, *freed);
        return;
    }

    for (auto const& [ptr, record] : m_allocations) {
        if (address >= ptr + record.size && address < ptr + record.size + redzone_size) {
            report_heap_overflow(address, ptr, record);
            return;
        }
    }
}

void MallocTracer::on_memory_read(u64 address)
{
    if (!m_enabled)
        return;
    if (m_active_function != Function::None || is_internal(m_emulator.cpu().rip()))
        return;

    // Reading memory that was freed is a use-after-free.
    if (auto const* freed = freed_allocation_containing(address)) {
        report_use_after_free_read(address, freed->ptr, *freed);
        return;
    }

    // Reading a live heap byte the guest never wrote is an uninitialized read.
    if (auto* record = live_allocation_containing(address)) {
        if (!record->initialized.empty()) {
            u64 offset = address - record->ptr;
            if (offset < record->initialized.size() && !record->initialized[static_cast<size_t>(offset)])
                report_uninitialized_read(address, record->ptr, *record);
        }
    }
}

MallocTracer::Function MallocTracer::detect_allocation_function_entry(u64 address) const
{
    if (m_emulator.m_malloc_symbol.start && address == m_emulator.m_malloc_symbol.start)
        return Function::Malloc;
    if (m_emulator.m_free_symbol.start && address == m_emulator.m_free_symbol.start)
        return Function::Free;
    if (m_emulator.m_realloc_symbol.start && address == m_emulator.m_realloc_symbol.start)
        return Function::Realloc;
    if (m_emulator.m_calloc_symbol.start && address == m_emulator.m_calloc_symbol.start)
        return Function::Calloc;
    return Function::None;
}

bool MallocTracer::is_in_libc(u64 address) const
{
    return m_emulator.is_in_libc(address);
}

// "Internal" code is the allocator/runtime (libc) and the dynamic loader; the
// tracer ignores reads, writes, and allocation calls originating there.
bool MallocTracer::is_internal(u64 address) const
{
    return m_emulator.is_in_libc(address) || m_emulator.is_in_loader(address);
}

// At a malloc/free/realloc/calloc entry the return address sits at the top of the
// stack (the prologue has not run yet); if that caller is internal, the call was
// not made by the guest.
bool MallocTracer::caller_is_internal() const
{
    u64 rsp = m_emulator.cpu().reg(SoftCPU64::RSP);
    try {
        return is_internal(m_emulator.mmu().read64(rsp));
    } catch (const EmulatorError&) {
        return false;
    }
}

void MallocTracer::report_double_free(u64 ptr, const AllocationRecord& record) const
{
    std::cerr << "\nmalloc-tracer ERROR: double free at " << hex(ptr)
              << " (size " << record.size << ")\n";
    std::cerr << "  allocation backtrace:\n";
    for (auto address : record.backtrace)
        std::cerr << "    " << m_emulator.symbolize(address) << "\n";
    std::cerr << "  free backtrace:\n";
    for (auto address : m_entry_backtrace)
        std::cerr << "    " << m_emulator.symbolize(address) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_invalid_free(u64 ptr) const
{
    std::cerr << "\nmalloc-tracer ERROR: invalid free at " << hex(ptr)
              << " (pointer was not allocated by malloc/calloc/realloc)\n";
    std::cerr << "  free backtrace:\n";
    for (auto address : m_entry_backtrace)
        std::cerr << "    " << m_emulator.symbolize(address) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_realloc_error(const char* message, u64 ptr, const AllocationRecord* record) const
{
    std::cerr << "\nmalloc-tracer ERROR: " << message << " " << hex(ptr) << "\n";
    if (record) {
        std::cerr << "  original allocation size was " << record->size << "\n";
        std::cerr << "  allocation backtrace:\n";
        for (auto address : record->backtrace)
            std::cerr << "    " << m_emulator.symbolize(address) << "\n";
    }
    std::cerr << "  realloc backtrace:\n";
    for (auto address : m_entry_backtrace)
        std::cerr << "    " << m_emulator.symbolize(address) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_heap_overflow(u64 address, u64 ptr, const AllocationRecord& record)
{
    std::ostringstream key;
    key << "overflow:" << hex(address);
    if (!m_reported_memory_errors.insert(key.str()).second)
        return;

    std::cerr << "\nmalloc-tracer ERROR: heap buffer overflow write at " << hex(address)
              << " for allocation " << hex(ptr) << " (size " << record.size << ")\n";
    std::cerr << "  allocation backtrace:\n";
    for (auto entry : record.backtrace)
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "  write backtrace:\n";
    for (auto entry : m_emulator.raw_backtrace())
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_use_after_free(u64 address, u64 ptr, const AllocationRecord& record)
{
    std::ostringstream key;
    key << "uaf:" << hex(address);
    if (!m_reported_memory_errors.insert(key.str()).second)
        return;

    std::cerr << "\nmalloc-tracer ERROR: use-after-free write at " << hex(address)
              << " for allocation " << hex(ptr) << " (size " << record.size << ")\n";
    std::cerr << "  allocation backtrace:\n";
    for (auto entry : record.backtrace)
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "  write backtrace:\n";
    for (auto entry : m_emulator.raw_backtrace())
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_use_after_free_read(u64 address, u64 ptr, const AllocationRecord& record)
{
    // Dedup per reading instruction so a loop reading freed memory reports once.
    std::ostringstream key;
    key << "uaf-read:" << hex(m_emulator.cpu().rip());
    if (!m_reported_memory_errors.insert(key.str()).second)
        return;

    std::cerr << "\nmalloc-tracer ERROR: use-after-free read at " << hex(address)
              << " for allocation " << hex(ptr) << " (size " << record.size << ")\n";
    std::cerr << "  allocation backtrace:\n";
    for (auto entry : record.backtrace)
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "  read backtrace:\n";
    for (auto entry : m_emulator.raw_backtrace())
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "\n";
}

void MallocTracer::report_uninitialized_read(u64 address, u64 ptr, const AllocationRecord& record)
{
    std::ostringstream key;
    key << "uninit-read:" << hex(m_emulator.cpu().rip());
    if (!m_reported_memory_errors.insert(key.str()).second)
        return;

    std::cerr << "\nmalloc-tracer ERROR: uninitialized heap read at " << hex(address)
              << " for allocation " << hex(ptr) << " (size " << record.size << ", offset "
              << (address - ptr) << ")\n";
    std::cerr << "  allocation backtrace:\n";
    for (auto entry : record.backtrace)
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "  read backtrace:\n";
    for (auto entry : m_emulator.raw_backtrace())
        std::cerr << "    " << m_emulator.symbolize(entry) << "\n";
    std::cerr << "\n";
}

const char* MallocTracer::function_name(Function function)
{
    switch (function) {
    case Function::Malloc:
        return "malloc";
    case Function::Free:
        return "free";
    case Function::Realloc:
        return "realloc";
    case Function::Calloc:
        return "calloc";
    case Function::None:
        return "none";
    }
    return "none";
}

std::set<u64> MallocTracer::compute_reachable_allocations() const
{
    std::set<u64> reachable;
    if (m_allocations.empty())
        return reachable;

    // Map a candidate pointer value to the live allocation that contains it.
    auto containing = [&](u64 value) -> u64 {
        auto it = m_allocations.upper_bound(value);
        if (it == m_allocations.begin())
            return 0;
        --it;
        if (value >= it->first && value < it->first + it->second.size)
            return it->first;
        return 0;
    };

    std::vector<u64> worklist;
    auto consider = [&](u64 value) {
        u64 base = containing(value);
        if (base != 0 && reachable.insert(base).second)
            worklist.push_back(base);
    };

    // Root set 1: CPU general-purpose registers.
    auto const& cpu = m_emulator.cpu();
    for (int i = 0; i < 16; ++i)
        consider(cpu.reg(i));

    // Root set 2: writable, non-heap memory (globals, stack, TLS, brk, allocator
    // metadata). Words that fall inside a live allocation are graph edges and are
    // walked in the BFS below, so skip them as roots.
    m_emulator.mmu().for_each_region([&](const SoftMMU::Region& region) {
        if (!region.writable() || region.size < 8)
            return;
        for (u64 offset = 0; offset + 8 <= region.size; offset += 8) {
            if (containing(region.base + offset) != 0)
                continue;
            u64 value = 0;
            for (int b = 0; b < 8; ++b)
                value |= static_cast<u64>(region.read_offset(offset + b)) << (b * 8);
            consider(value);
        }
    });

    // BFS through reachable allocation contents to mark transitively reachable
    // allocations (pointers stored inside one heap block into another).
    while (!worklist.empty()) {
        u64 base = worklist.back();
        worklist.pop_back();
        auto it = m_allocations.find(base);
        if (it == m_allocations.end())
            continue;
        u64 size = it->second.size;
        for (u64 offset = 0; offset + 8 <= size; offset += 8)
            consider(m_emulator.mmu().read64(base + offset));
    }
    return reachable;
}

void MallocTracer::dump_leak_report(std::ostream& stream) const
{
    if (!m_enabled)
        return;

    if (m_allocations.empty()) {
        stream << "malloc-tracer: no leaks detected\n";
        return;
    }

    auto reachable = compute_reachable_allocations();

    size_t total_leaked = 0;
    size_t lost_count = 0;
    for (auto const& [ptr, record] : m_allocations) {
        total_leaked += static_cast<size_t>(record.size);
        if (!reachable.contains(ptr))
            ++lost_count;
    }

    stream << "\nmalloc-tracer: " << m_allocations.size() << " leak(s) detected, "
           << total_leaked << " byte(s) total"
           << " (" << lost_count << " definitely lost, "
           << (m_allocations.size() - lost_count) << " still reachable)\n";

    for (auto const& [ptr, record] : m_allocations) {
        bool is_reachable = reachable.contains(ptr);
        stream << "  leak: " << record.size << " byte(s) at " << hex(ptr)
               << (is_reachable ? " (still reachable)" : " (definitely lost)") << "\n";
        stream << "  allocated at:\n";
        for (auto address : record.backtrace)
            stream << "    " << m_emulator.symbolize(address) << "\n";
    }
    stream << "\n";
}

void MallocTracer::dump_event_log(std::ostream& stream) const
{
    if (!m_enabled)
        return;

    size_t total_live = 0;
    for (auto const& [ptr, record] : m_allocations)
        total_live += static_cast<size_t>(record.size);

    stream << "malloc-tracer: " << m_allocations.size() << " live allocation(s), "
           << m_freed.size() << " freed allocation(s)\n";
    stream << "malloc-tracer: " << total_live << " byte(s) still allocated\n";
}

}
