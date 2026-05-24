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
#include <signal.h>
#include <sys/syscall.h>
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

static constexpr u64 signal_frame_magic = 0x4c55455349474652ULL; // "LUESIGFR"
static constexpr u64 signal_trampoline_address = 0x7fffff100000ULL;
static constexpr u64 signal_frame_size = 8 * (1 + 1 + 1 + 1 + 16 + 1 + 1);
static volatile sig_atomic_t s_host_signal_pending[NSIG] {};

enum SignalFrameOffset : u64 {
    SignalFrameMagic = 0,
    SignalFrameMask = 8,
    SignalFrameRip = 16,
    SignalFrameRflags = 24,
    SignalFrameGpr = 32,
    SignalFrameFsBase = SignalFrameGpr + 16 * 8,
    SignalFrameGsBase = SignalFrameFsBase + 8,
};

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

bool is_exit_syscall(u64 number)
{
#ifdef SYS_exit
    if (number == SYS_exit)
        return true;
#endif
#ifdef SYS_exit_group
    if (number == SYS_exit_group)
        return true;
#endif
    return false;
}

u64 signal_bit(int signum)
{
    if (signum <= 0 || signum >= 64)
        return 0;
    return 1ULL << (signum - 1);
}

bool default_signal_is_ignored(int signum)
{
    return signum == SIGCHLD || signum == SIGURG || signum == SIGWINCH;
}

void host_signal_handler(int signum)
{
    if (signum > 0 && signum < NSIG)
        s_host_signal_pending[signum] = 1;
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
            collect_host_signals();
            dispatch_pending_signal();
        }
    } catch (const GuestExit& exit) {
        if (m_options.backtrace_on_exit) {
            if (!m_last_non_exit_syscall_backtrace.empty()) {
                std::cerr << "guest exit backtrace (last non-exit syscall):\n";
                dump_backtrace(m_last_non_exit_syscall_backtrace);
            } else {
                std::cerr << "guest exit backtrace:\n";
                dump_backtrace();
            }
        }
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
    setup_signal_trampoline();
    register_host_signal_handlers();

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
    if (m_options.backtrace_on_exit && !is_exit_syscall(number))
        m_last_non_exit_syscall_backtrace = raw_backtrace();
    return LinuxSyscalls::dispatch(*this, number);
}

void Emulator::setup_signal_trampoline()
{
    static constexpr std::array<u8, 11> trampoline {
        0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov $15, %rax
        0x0f, 0x05,                               // syscall
        0xf4,                                     // hlt
        0x90,                                     // nop
    };
    m_mmu.map_bytes(signal_trampoline_address, page_size, ProtRead | ProtExecute, trampoline.data(), trampoline.size(), 0, "[signal trampoline]");
    m_signal_trampoline = signal_trampoline_address;
}

void Emulator::register_host_signal_handlers()
{
    auto register_one = [](int signum) {
        struct sigaction action {};
        action.sa_handler = host_signal_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(signum, &action, nullptr);
    };

    register_one(SIGHUP);
    register_one(SIGINT);
    register_one(SIGQUIT);
    register_one(SIGTERM);
    register_one(SIGUSR1);
    register_one(SIGUSR2);
    register_one(SIGALRM);
}

void Emulator::collect_host_signals()
{
    for (int signum = 1; signum < NSIG && signum < 64; ++signum) {
        if (!s_host_signal_pending[signum])
            continue;
        s_host_signal_pending[signum] = 0;
        deliver_signal(signum);
    }
}

bool Emulator::is_signal_blocked(int signum) const
{
    return (m_signal_mask & signal_bit(signum)) != 0;
}

void Emulator::dispatch_pending_signal()
{
    for (int signum = 1; signum < NSIG && signum < 64; ++signum) {
        auto bit = signal_bit(signum);
        if (!(m_pending_signals & bit) || is_signal_blocked(signum))
            continue;

        m_pending_signals &= ~bit;
        auto const& action = m_signal_actions[static_cast<size_t>(signum)];

        if (action.handler == 1)
            return;
        if (action.handler == 0) {
            if (default_signal_is_ignored(signum))
                return;
            throw GuestExit(128 + signum);
        }

        u64 old_rsp = m_cpu.reg(SoftCPU64::RSP);
        u64 frame = (old_rsp - signal_frame_size - 128) & ~0xfULL;
        u64 handler_rsp = frame - 8;
        u64 restorer = action.restorer ? action.restorer : m_signal_trampoline;

        m_mmu.write64(handler_rsp, restorer);
        m_mmu.write64(frame + SignalFrameMagic, signal_frame_magic);
        m_mmu.write64(frame + SignalFrameMask, m_signal_mask);
        m_mmu.write64(frame + SignalFrameRip, m_cpu.rip());
        m_mmu.write64(frame + SignalFrameRflags, m_cpu.rflags());
        for (int i = 0; i < 16; ++i)
            m_mmu.write64(frame + SignalFrameGpr + static_cast<u64>(i) * 8, m_cpu.reg(i));
        m_mmu.write64(frame + SignalFrameFsBase, m_cpu.fs_base());
        m_mmu.write64(frame + SignalFrameGsBase, m_cpu.gs_base());

        m_signal_mask |= action.mask;
        m_signal_mask |= bit;

        m_cpu.set_reg(SoftCPU64::RDI, static_cast<u64>(signum));
        m_cpu.set_reg(SoftCPU64::RSI, 0);
        m_cpu.set_reg(SoftCPU64::RDX, 0);
        m_cpu.set_reg(SoftCPU64::RSP, handler_rsp);
        m_cpu.set_rip(action.handler);
        m_cpu.push_synthetic_return(restorer);
        return;
    }
}

int Emulator::set_signal_action(int signum, bool update_action, u64 handler, u64 flags, u64 restorer, u64 mask, u64 old_action_address)
{
    if (signum <= 0 || signum >= NSIG || signum >= 64)
        return -EINVAL;
    if (signum == SIGKILL || signum == SIGSTOP)
        return -EINVAL;

    if (old_action_address) {
        auto const& old_action = m_signal_actions[static_cast<size_t>(signum)];
        m_mmu.write64(old_action_address + 0, old_action.handler);
        m_mmu.write64(old_action_address + 8, old_action.flags);
        m_mmu.write64(old_action_address + 16, old_action.restorer);
        m_mmu.write64(old_action_address + 24, old_action.mask);
    }

    if (update_action)
        m_signal_actions[static_cast<size_t>(signum)] = { handler, flags, restorer, mask };
    return 0;
}

int Emulator::set_signal_mask(int how, u64 set_address, u64 old_set_address)
{
    if (old_set_address)
        m_mmu.write64(old_set_address, m_signal_mask);
    if (!set_address)
        return 0;

    u64 new_mask = m_mmu.read64(set_address);
    new_mask &= ~signal_bit(SIGKILL);
    new_mask &= ~signal_bit(SIGSTOP);

    switch (how) {
    case 0:
        m_signal_mask |= new_mask;
        return 0;
    case 1:
        m_signal_mask &= ~new_mask;
        return 0;
    case 2:
        m_signal_mask = new_mask;
        return 0;
    default:
        return -EINVAL;
    }
}

int Emulator::deliver_signal(int signum)
{
    if (signum <= 0 || signum >= NSIG || signum >= 64)
        return -EINVAL;
    m_pending_signals |= signal_bit(signum);
    return 0;
}

u64 Emulator::handle_sigreturn()
{
    u64 frame = m_cpu.reg(SoftCPU64::RSP);
    if (m_mmu.read64(frame + SignalFrameMagic) != signal_frame_magic)
        throw EmulatorError("invalid guest signal frame at " + hex(frame));

    m_signal_mask = m_mmu.read64(frame + SignalFrameMask);
    u64 restored_rip = m_mmu.read64(frame + SignalFrameRip);
    u64 restored_rflags = m_mmu.read64(frame + SignalFrameRflags);
    std::array<u64, 16> restored_regs {};
    for (int i = 0; i < 16; ++i)
        restored_regs[static_cast<size_t>(i)] = m_mmu.read64(frame + SignalFrameGpr + static_cast<u64>(i) * 8);
    u64 restored_fs = m_mmu.read64(frame + SignalFrameFsBase);
    u64 restored_gs = m_mmu.read64(frame + SignalFrameGsBase);

    for (int i = 0; i < 16; ++i)
        m_cpu.set_reg(i, restored_regs[static_cast<size_t>(i)]);
    m_cpu.set_fs_base(restored_fs);
    m_cpu.set_gs_base(restored_gs);
    m_cpu.set_rflags(restored_rflags);
    m_cpu.set_rip(restored_rip);
    m_restored_context_from_sigreturn = true;
    return restored_regs[SoftCPU64::RAX];
}

bool Emulator::consume_restored_context_from_sigreturn()
{
    bool value = m_restored_context_from_sigreturn;
    m_restored_context_from_sigreturn = false;
    return value;
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

    auto append_address = [&](u64 address) {
        if (address && std::find(backtrace.begin(), backtrace.end(), address) == backtrace.end())
            backtrace.push_back(address);
    };

    auto const& call_stack = m_cpu.call_stack();
    for (auto it = call_stack.rbegin(); it != call_stack.rend() && backtrace.size() < 128; ++it)
        append_address(*it);

    u64 frame = m_cpu.reg(SoftCPU64::RBP);
    for (size_t depth = 0; depth < 127 && frame; ++depth) {
        if (!m_mmu.is_mapped(frame, 16))
            break;
        u64 next_frame = m_mmu.read64(frame);
        u64 return_address = m_mmu.read64(frame + 8);
        if (!return_address)
            break;
        append_address(return_address);
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
