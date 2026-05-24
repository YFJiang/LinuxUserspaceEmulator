#pragma once

#include "ELFLoader.h"
#include "SoftCPU64.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace LUE {

struct EmulatorOptions {
    bool trace { false };
    bool trace_syscalls { false };
};

class Emulator {
public:
    Emulator(std::string executable_path, std::vector<std::string> arguments, std::vector<std::string> environment, EmulatorOptions);

    int exec();
    u64 handle_syscall(u64 number);

    SoftMMU& mmu() { return m_mmu; }
    const SoftMMU& mmu() const { return m_mmu; }
    SoftCPU64& cpu() { return m_cpu; }
    const SoftCPU64& cpu() const { return m_cpu; }
    const LoadedProgram& program() const { return m_program; }
    const EmulatorOptions& options() const { return m_options; }

    u64 brk() const { return m_brk; }
    u64 set_brk(u64 requested);

    void register_host_fd(int guest_fd);
    void unregister_host_fd(int guest_fd);
    std::optional<std::string> path_for_fd(int guest_fd) const;
    void register_mapped_file(const std::string& path, u64 mapped_address);

    std::vector<u64> raw_backtrace() const;
    std::string symbolize(u64 address) const;
    void dump_backtrace() const;
    void dump_backtrace(const std::vector<u64>&) const;

    bool is_in_loader_code() const;
    bool is_in_libc() const;
    bool is_in_libsystem() const;
    bool is_in_malloc_or_free() const;

    void dump_state() const;

private:
    struct SymbolRange {
        u64 start { 0 };
        u64 end { 0 };
        std::string name;

        bool contains(u64 address) const { return address >= start && address < end; }
    };

    struct LoadedImage {
        std::string path;
        std::string name;
        std::string kind;
        u64 base { 0 };
        u64 end { 0 };
        std::vector<std::pair<u64, u64>> executable_ranges;
        std::vector<SymbolRange> symbols;

        bool contains(u64 address) const { return address >= base && address < end; }
        bool contains_code(u64 address) const;
    };

    void load();
    void setup_stack();
    void push64(u64 value);
    u64 push_bytes(const void* data, size_t size);
    u64 push_string(const std::string& value);
    void register_loaded_image(const std::string& path, u64 load_base, std::string kind = {});
    const LoadedImage* image_containing(u64 address) const;
    const SymbolRange* symbol_containing(const LoadedImage&, u64 address) const;
    std::string describe_address(u64 address) const;
    bool address_in_range(u64 address, const SymbolRange&) const;

    std::string m_executable_path;
    std::vector<std::string> m_arguments;
    std::vector<std::string> m_environment;
    EmulatorOptions m_options;

    SoftMMU m_mmu;
    SoftCPU64 m_cpu;
    LoadedProgram m_program;

    u64 m_stack_base { 0x7fffff000000ULL };
    u64 m_stack_size { 8 * 1024 * 1024ULL };
    u64 m_stack_top { 0 };

    u64 m_brk_start { 0 };
    u64 m_brk { 0 };
    u64 m_brk_region_end { 0 };

    std::map<int, std::string> m_fd_paths;
    std::vector<LoadedImage> m_loaded_images;
    SymbolRange m_malloc_symbol;
    SymbolRange m_realloc_symbol;
    SymbolRange m_calloc_symbol;
    SymbolRange m_free_symbol;
    SymbolRange m_malloc_usable_size_symbol;
};

}
