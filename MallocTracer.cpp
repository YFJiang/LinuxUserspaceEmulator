#include "MallocTracer.h"

#include "Emulator.h"
#include "SoftCPU64.h"
#include "SoftMMU.h"

#include <iostream>
#include <sstream>

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
    bool in_libc = is_in_libc(rip);

    if (m_active_function == Function::None) {
        if (current != Function::None) {
            m_active_function = current;
            on_function_enter(current);
        }
        return;
    }

    if (!in_libc && current == Function::None) {
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

    record_allocation(result, m_entry_args[0]);

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
            record_allocation(result, new_size);
        return;
    }

    if (new_size == 0) {
        if (m_allocations.contains(old_ptr))
            move_to_freed(old_ptr);
        return;
    }

    auto it = m_allocations.find(old_ptr);
    if (it != m_allocations.end()) {
        move_to_freed(old_ptr);
    } else {
        auto freed_it = m_freed.find(old_ptr);
        if (freed_it != m_freed.end())
            report_realloc_error("realloc of freed pointer", old_ptr, &freed_it->second);
        else
            report_realloc_error("realloc of unknown pointer", old_ptr);
    }

    if (result != 0)
        record_allocation(result, new_size);

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
    record_allocation(result, total);

    if (m_emulator.options().trace_syscalls)
        std::cerr << "malloc-tracer: calloc(" << nmemb << ", " << elem_size << ") = " << hex(result) << "\n";
}

void MallocTracer::record_allocation(u64 ptr, u64 size)
{
    AllocationRecord record;
    record.ptr = ptr;
    record.size = size;
    record.backtrace = m_entry_backtrace;
    record.freed = false;

    m_allocations[ptr] = record;
    m_freed.erase(ptr);

    try {
        m_emulator.mmu().mark_initialized(ptr, static_cast<size_t>(size), true);
    } catch (const EmulatorError&) {
    }
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
    if (m_active_function != Function::None || is_in_libc(m_emulator.cpu().rip()))
        return;

    for (auto const& [ptr, record] : m_freed) {
        if (address >= ptr && address < ptr + record.size) {
            report_use_after_free(address, ptr, record);
            return;
        }
    }

    for (auto const& [ptr, record] : m_allocations) {
        if (address >= ptr + record.size && address < ptr + record.size + redzone_size) {
            report_heap_overflow(address, ptr, record);
            return;
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

void MallocTracer::dump_leak_report(std::ostream& stream) const
{
    if (!m_enabled)
        return;

    if (m_allocations.empty()) {
        stream << "malloc-tracer: no leaks detected\n";
        return;
    }

    size_t total_leaked = 0;
    for (auto const& [ptr, record] : m_allocations)
        total_leaked += static_cast<size_t>(record.size);

    stream << "\nmalloc-tracer: " << m_allocations.size() << " leak(s) detected, "
           << total_leaked << " byte(s) total\n";

    for (auto const& [ptr, record] : m_allocations) {
        stream << "  leak: " << record.size << " byte(s) at " << hex(ptr) << "\n";
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
