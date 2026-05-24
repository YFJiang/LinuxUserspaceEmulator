#include "Emulator.h"

#include "ELFSymbols.h"
#include "LinuxSyscalls.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>

namespace LUE {
namespace {

static constexpr u64 AT_NULL = 0;
static constexpr u64 AT_PHDR = 3;
static constexpr u64 AT_PHENT = 4;
static constexpr u64 AT_PHNUM = 5;
static constexpr u64 AT_PAGESZ = 6;
static constexpr u64 AT_BASE = 7;
static constexpr u64 AT_FLAGS = 8;
static constexpr u64 AT_ENTRY = 9;
static constexpr u64 AT_UID = 11;
static constexpr u64 AT_EUID = 12;
static constexpr u64 AT_GID = 13;
static constexpr u64 AT_EGID = 14;
static constexpr u64 AT_PLATFORM = 15;
static constexpr u64 AT_HWCAP = 16;
static constexpr u64 AT_CLKTCK = 17;
static constexpr u64 AT_SECURE = 23;
static constexpr u64 AT_RANDOM = 25;
static constexpr u64 AT_HWCAP2 = 26;
static constexpr u64 AT_EXECFN = 31;

std::string basename(const std::string& path)
{
    auto slash = path.find_last_of('/');
    if (slash == std::string::npos)
        return path;
    return path.substr(slash + 1);
}

std::string image_kind_for_path(const std::string& path)
{
    auto name = basename(path);
    if (name == "ld-linux-x86-64.so.2" || name.rfind("ld-", 0) == 0)
        return "loader";
    if (name == "libc.so.6" || name.rfind("libc-", 0) == 0)
        return "libc";
    if (name.find("libsystem") != std::string::npos)
        return "libsystem";
    return {};
}

std::optional<std::string> path_from_host_fd(int fd)
{
    char proc_path[64];
    std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    std::array<char, 4096> path {};
    auto length = ::readlink(proc_path, path.data(), path.size() - 1);
    if (length < 0)
        return {};
    path[static_cast<size_t>(length)] = '\0';
    return std::string(path.data());
}

}

Emulator::Emulator(std::string executable_path, std::vector<std::string> arguments, std::vector<std::string> environment, EmulatorOptions options)
    : m_executable_path(std::move(executable_path))
    , m_arguments(std::move(arguments))
    , m_environment(std::move(environment))
    , m_options(options)
    , m_cpu(*this)
{
}

int Emulator::exec()
{
    try {
        load();
        while (true) {
            if (m_options.trace) {
                auto instruction = m_cpu.current_instruction_text();
                std::cerr << "instruction: " << instruction << "\n";
                m_cpu.step();
                m_cpu.dump(std::cerr);
            } else {
                m_cpu.step();
            }
        }
    } catch (const GuestExit& exit) {
        return exit.status();
    } catch (const EmulatorError& error) {
        std::cerr << "\nLinuxUserspaceEmulator: " << error.what() << "\n";
        dump_state();
        return 127;
    }
}

void Emulator::load()
{
    m_program = ELFLoader::load(m_mmu, m_executable_path);
    register_loaded_image(m_program.executable_path, m_program.executable_base, "executable");
    if (m_program.dynamic && !m_program.interpreter_path.empty())
        register_loaded_image(m_program.interpreter_path, m_program.interpreter_base, "loader");

    m_brk_start = page_align_up(m_program.brk_start);
    m_brk = m_brk_start;
    m_brk_region_end = m_brk_start;

    u64 stack_low = m_stack_base - m_stack_size;
    m_mmu.map_zeroed(stack_low, m_stack_size, ProtRead | ProtWrite, "[stack]");
    m_stack_top = m_stack_base;
    setup_stack();

    m_cpu.set_rip(m_program.entry);
    m_cpu.set_reg(SoftCPU64::RSP, m_stack_top);
}

void Emulator::push64(u64 value)
{
    m_stack_top -= 8;
    m_mmu.write64(m_stack_top, value);
}

u64 Emulator::push_bytes(const void* data, size_t size)
{
    m_stack_top -= size;
    m_mmu.copy_to_guest(m_stack_top, data, size);
    return m_stack_top;
}

u64 Emulator::push_string(const std::string& value)
{
    return push_bytes(value.c_str(), value.size() + 1);
}

void Emulator::setup_stack()
{
    std::vector<u64> argv;
    std::vector<u64> envp;

    for (auto it = m_arguments.rbegin(); it != m_arguments.rend(); ++it)
        argv.push_back(push_string(*it));
    std::reverse(argv.begin(), argv.end());

    for (auto it = m_environment.rbegin(); it != m_environment.rend(); ++it)
        envp.push_back(push_string(*it));
    std::reverse(envp.begin(), envp.end());

    u64 execfn = push_string(m_executable_path);
    u64 platform = push_string("x86_64");

    std::array<u8, 16> random {};
    for (size_t i = 0; i < random.size(); ++i)
        random[i] = static_cast<u8>(std::rand() & 0xff);
    u64 random_address = push_bytes(random.data(), random.size());

    m_stack_top &= ~0xfULL;

    std::vector<std::pair<u64, u64>> auxv;
    auxv.push_back({ AT_PHDR, m_program.phdr });
    auxv.push_back({ AT_PHENT, m_program.phent });
    auxv.push_back({ AT_PHNUM, m_program.phnum });
    auxv.push_back({ AT_PAGESZ, page_size });
    auxv.push_back({ AT_BASE, m_program.interpreter_base });
    auxv.push_back({ AT_FLAGS, 0 });
    auxv.push_back({ AT_ENTRY, m_program.executable_entry });
    auxv.push_back({ AT_UID, static_cast<u64>(getuid()) });
    auxv.push_back({ AT_EUID, static_cast<u64>(geteuid()) });
    auxv.push_back({ AT_GID, static_cast<u64>(getgid()) });
    auxv.push_back({ AT_EGID, static_cast<u64>(getegid()) });
    auxv.push_back({ AT_PLATFORM, platform });
    auxv.push_back({ AT_HWCAP, 0 });
    auxv.push_back({ AT_CLKTCK, static_cast<u64>(sysconf(_SC_CLK_TCK)) });
    auxv.push_back({ AT_SECURE, 0 });
    auxv.push_back({ AT_RANDOM, random_address });
    auxv.push_back({ AT_HWCAP2, 0 });
    auxv.push_back({ AT_EXECFN, execfn });
    auxv.push_back({ AT_NULL, 0 });

    for (auto it = auxv.rbegin(); it != auxv.rend(); ++it) {
        push64(it->second);
        push64(it->first);
    }

    push64(0);
    for (auto it = envp.rbegin(); it != envp.rend(); ++it)
        push64(*it);

    push64(0);
    for (auto it = argv.rbegin(); it != argv.rend(); ++it)
        push64(*it);

    push64(argv.size());
}

u64 Emulator::set_brk(u64 requested)
{
    if (requested == 0)
        return m_brk;
    if (requested < m_brk_start)
        return m_brk;
    if (requested > m_brk_region_end) {
        u64 new_end = page_align_up(requested);
        if (new_end > m_brk_region_end) {
            m_mmu.map_zeroed(m_brk_region_end, new_end - m_brk_region_end, ProtRead | ProtWrite, "[brk]");
            m_brk_region_end = new_end;
        }
    }
    m_brk = requested;
    return m_brk;
}

u64 Emulator::handle_syscall(u64 number)
{
    return LinuxSyscalls::dispatch(*this, number);
}

bool Emulator::LoadedImage::contains_code(u64 address) const
{
    for (auto const& range : executable_ranges) {
        if (address >= range.first && address < range.second)
            return true;
    }
    return false;
}

void Emulator::register_host_fd(int guest_fd)
{
    auto path = path_from_host_fd(guest_fd);
    if (path.has_value())
        m_fd_paths[guest_fd] = path.value();
}

void Emulator::unregister_host_fd(int guest_fd)
{
    m_fd_paths.erase(guest_fd);
}

std::optional<std::string> Emulator::path_for_fd(int guest_fd) const
{
    auto it = m_fd_paths.find(guest_fd);
    if (it == m_fd_paths.end())
        return {};
    return it->second;
}

void Emulator::register_mapped_file(const std::string& path, u64 mapped_address)
{
    if (!path.empty())
        register_loaded_image(path, mapped_address);
}

void Emulator::register_loaded_image(const std::string& path, u64 load_base, std::string kind)
{
    if (path.empty())
        return;
    for (auto const& image : m_loaded_images) {
        if (image.path == path && image.base == load_base)
            return;
    }

    ELFImageInfo info;
    try {
        info = read_elf_image_info(path);
    } catch (const EmulatorError&) {
        return;
    }

    LoadedImage image;
    image.path = path;
    image.name = basename(path);
    image.kind = kind.empty() ? image_kind_for_path(path) : std::move(kind);
    image.base = load_base - info.min_vaddr;
    image.end = image.base + info.max_vaddr;
    for (auto const& range : info.executable_ranges)
        image.executable_ranges.push_back({ image.base + range.first, image.base + range.second });
    for (auto const& symbol : info.function_symbols) {
        u64 start = image.base + symbol.value;
        u64 size = symbol.size ? symbol.size : 1;
        image.symbols.push_back({ start, start + size, symbol.name });
    }

    auto remember_malloc_symbol = [&](const std::string& name, SymbolRange& target) {
        auto it = std::find_if(image.symbols.begin(), image.symbols.end(), [&](auto const& symbol) {
            return symbol.name == name;
        });
        if (it != image.symbols.end())
            target = *it;
    };

    if (image.kind == "libc") {
        remember_malloc_symbol("malloc", m_malloc_symbol);
        remember_malloc_symbol("realloc", m_realloc_symbol);
        remember_malloc_symbol("calloc", m_calloc_symbol);
        remember_malloc_symbol("free", m_free_symbol);
        remember_malloc_symbol("malloc_usable_size", m_malloc_usable_size_symbol);
    }

    m_loaded_images.push_back(std::move(image));
}

const Emulator::LoadedImage* Emulator::image_containing(u64 address) const
{
    for (auto const& image : m_loaded_images) {
        if (image.contains(address))
            return &image;
    }
    return nullptr;
}

const Emulator::SymbolRange* Emulator::symbol_containing(const LoadedImage& image, u64 address) const
{
    const SymbolRange* best = nullptr;
    for (auto const& symbol : image.symbols) {
        if (!symbol.contains(address))
            continue;
        if (!best || symbol.start > best->start)
            best = &symbol;
    }
    return best;
}

std::string Emulator::describe_address(u64 address) const
{
    auto* image = image_containing(address);
    if (!image)
        return hex(address);

    std::ostringstream builder;
    builder << hex(address) << " [" << image->name << "]";

    if (auto* symbol = symbol_containing(*image, address)) {
        builder << ": " << symbol->name;
        u64 offset = address - symbol->start;
        if (offset)
            builder << "+" << hex(offset);
    } else {
        builder << ": " << hex(address - image->base);
    }
    return builder.str();
}

std::string Emulator::symbolize(u64 address) const
{
    return describe_address(address);
}

std::vector<u64> Emulator::raw_backtrace() const
{
    std::vector<u64> backtrace;
    backtrace.push_back(m_cpu.rip());

    u64 frame = m_cpu.reg(SoftCPU64::RBP);
    for (size_t depth = 0; depth < 127 && frame; ++depth) {
        if (!m_mmu.is_mapped(frame, 16))
            break;
        u64 next_frame = m_mmu.read64(frame);
        u64 return_address = m_mmu.read64(frame + 8);
        if (!return_address)
            break;
        backtrace.push_back(return_address);
        if (next_frame <= frame)
            break;
        frame = next_frame;
    }

    return backtrace;
}

void Emulator::dump_backtrace(const std::vector<u64>& backtrace) const
{
    for (auto address : backtrace)
        std::cerr << "  " << describe_address(address) << "\n";
}

void Emulator::dump_backtrace() const
{
    dump_backtrace(raw_backtrace());
}

bool Emulator::address_in_range(u64 address, const SymbolRange& range) const
{
    return range.start && range.contains(address);
}

bool Emulator::is_in_loader_code() const
{
    auto* image = image_containing(m_cpu.rip());
    return image && image->kind == "loader" && image->contains_code(m_cpu.rip());
}

bool Emulator::is_in_libc() const
{
    auto* image = image_containing(m_cpu.rip());
    return image && image->kind == "libc";
}

bool Emulator::is_in_libsystem() const
{
    auto* image = image_containing(m_cpu.rip());
    return image && image->kind == "libsystem";
}

bool Emulator::is_in_malloc_or_free() const
{
    u64 rip = m_cpu.rip();
    return address_in_range(rip, m_malloc_symbol)
        || address_in_range(rip, m_realloc_symbol)
        || address_in_range(rip, m_calloc_symbol)
        || address_in_range(rip, m_free_symbol)
        || address_in_range(rip, m_malloc_usable_size_symbol);
}

void Emulator::dump_state() const
{
    m_cpu.dump(std::cerr);
    std::cerr << "backtrace:\n";
    dump_backtrace();
    std::cerr << "mapped regions:\n";
    m_mmu.dump_regions(std::cerr);
}

}
