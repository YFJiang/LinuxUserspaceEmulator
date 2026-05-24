#include "LinuxSyscalls.h"

#include "Emulator.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#    include <asm/prctl.h>
#    include <linux/futex.h>
#endif

#ifndef SYS_pread64
#    ifdef __NR_pread64
#        define SYS_pread64 __NR_pread64
#    else
#        define SYS_pread64 17
#    endif
#endif

#ifndef SYS_pwrite64
#    ifdef __NR_pwrite64
#        define SYS_pwrite64 __NR_pwrite64
#    else
#        define SYS_pwrite64 18
#    endif
#endif

#ifndef SYS_access
#    ifdef __NR_access
#        define SYS_access __NR_access
#    else
#        define SYS_access 21
#    endif
#endif

namespace LUE {
namespace {

u64 syscall_error(int err)
{
    return static_cast<u64>(-static_cast<i64>(err));
}

u64 syscall_result(long rc)
{
    if (rc < 0)
        return syscall_error(errno);
    return static_cast<u64>(rc);
}

const char* syscall_name(u64 number)
{
    switch (number) {
#ifdef SYS_read
    case SYS_read:
        return "read";
#endif
#ifdef SYS_write
    case SYS_write:
        return "write";
#endif
#ifdef SYS_readv
    case SYS_readv:
        return "readv";
#endif
#ifdef SYS_writev
    case SYS_writev:
        return "writev";
#endif
#ifdef SYS_pread64
    case SYS_pread64:
        return "pread64";
#endif
#ifdef SYS_pwrite64
    case SYS_pwrite64:
        return "pwrite64";
#endif
#ifdef SYS_open
    case SYS_open:
        return "open";
#endif
#ifdef SYS_openat
    case SYS_openat:
        return "openat";
#endif
#ifdef SYS_close
    case SYS_close:
        return "close";
#endif
#ifdef SYS_dup
    case SYS_dup:
        return "dup";
#endif
#ifdef SYS_dup2
    case SYS_dup2:
        return "dup2";
#endif
#ifdef SYS_dup3
    case SYS_dup3:
        return "dup3";
#endif
#ifdef SYS_pipe
    case SYS_pipe:
        return "pipe";
#endif
#ifdef SYS_pipe2
    case SYS_pipe2:
        return "pipe2";
#endif
#ifdef SYS_fcntl
    case SYS_fcntl:
        return "fcntl";
#endif
#ifdef SYS_lseek
    case SYS_lseek:
        return "lseek";
#endif
#ifdef SYS_stat
    case SYS_stat:
        return "stat";
#endif
#ifdef SYS_lstat
    case SYS_lstat:
        return "lstat";
#endif
#ifdef SYS_fstat
    case SYS_fstat:
        return "fstat";
#endif
#ifdef SYS_newfstatat
    case SYS_newfstatat:
        return "newfstatat";
#endif
#ifdef SYS_mmap
    case SYS_mmap:
        return "mmap";
#endif
#ifdef SYS_munmap
    case SYS_munmap:
        return "munmap";
#endif
#ifdef SYS_mprotect
    case SYS_mprotect:
        return "mprotect";
#endif
#ifdef SYS_brk
    case SYS_brk:
        return "brk";
#endif
#ifdef SYS_arch_prctl
    case SYS_arch_prctl:
        return "arch_prctl";
#endif
#ifdef SYS_exit
    case SYS_exit:
        return "exit";
#endif
#ifdef SYS_exit_group
    case SYS_exit_group:
        return "exit_group";
#endif
#ifdef SYS_getpid
    case SYS_getpid:
        return "getpid";
#endif
#ifdef SYS_getuid
    case SYS_getuid:
        return "getuid";
#endif
#ifdef SYS_geteuid
    case SYS_geteuid:
        return "geteuid";
#endif
#ifdef SYS_getgid
    case SYS_getgid:
        return "getgid";
#endif
#ifdef SYS_getegid
    case SYS_getegid:
        return "getegid";
#endif
#ifdef SYS_gettid
    case SYS_gettid:
        return "gettid";
#endif
#ifdef SYS_getppid
    case SYS_getppid:
        return "getppid";
#endif
#ifdef SYS_getpgid
    case SYS_getpgid:
        return "getpgid";
#endif
#ifdef SYS_getpgrp
    case SYS_getpgrp:
        return "getpgrp";
#endif
#ifdef SYS_getcwd
    case SYS_getcwd:
        return "getcwd";
#endif
#ifdef SYS_ioctl
    case SYS_ioctl:
        return "ioctl";
#endif
#ifdef SYS_poll
    case SYS_poll:
        return "poll";
#endif
#ifdef SYS_ppoll
    case SYS_ppoll:
        return "ppoll";
#endif
#ifdef SYS_select
    case SYS_select:
        return "select";
#endif
#ifdef SYS_pselect6
    case SYS_pselect6:
        return "pselect6";
#endif
#ifdef SYS_epoll_create1
    case SYS_epoll_create1:
        return "epoll_create1";
#endif
#ifdef SYS_epoll_ctl
    case SYS_epoll_ctl:
        return "epoll_ctl";
#endif
#ifdef SYS_epoll_wait
    case SYS_epoll_wait:
        return "epoll_wait";
#endif
#ifdef SYS_epoll_pwait
    case SYS_epoll_pwait:
        return "epoll_pwait";
#endif
#ifdef SYS_socket
    case SYS_socket:
        return "socket";
#endif
#ifdef SYS_socketpair
    case SYS_socketpair:
        return "socketpair";
#endif
#ifdef SYS_bind
    case SYS_bind:
        return "bind";
#endif
#ifdef SYS_listen
    case SYS_listen:
        return "listen";
#endif
#ifdef SYS_accept
    case SYS_accept:
        return "accept";
#endif
#ifdef SYS_accept4
    case SYS_accept4:
        return "accept4";
#endif
#ifdef SYS_connect
    case SYS_connect:
        return "connect";
#endif
#ifdef SYS_getsockname
    case SYS_getsockname:
        return "getsockname";
#endif
#ifdef SYS_getpeername
    case SYS_getpeername:
        return "getpeername";
#endif
#ifdef SYS_setsockopt
    case SYS_setsockopt:
        return "setsockopt";
#endif
#ifdef SYS_getsockopt
    case SYS_getsockopt:
        return "getsockopt";
#endif
#ifdef SYS_sendto
    case SYS_sendto:
        return "sendto";
#endif
#ifdef SYS_recvfrom
    case SYS_recvfrom:
        return "recvfrom";
#endif
#ifdef SYS_shutdown
    case SYS_shutdown:
        return "shutdown";
#endif
#ifdef SYS_clock_gettime
    case SYS_clock_gettime:
        return "clock_gettime";
#endif
#ifdef SYS_clock_nanosleep
    case SYS_clock_nanosleep:
        return "clock_nanosleep";
#endif
#ifdef SYS_gettimeofday
    case SYS_gettimeofday:
        return "gettimeofday";
#endif
#ifdef SYS_nanosleep
    case SYS_nanosleep:
        return "nanosleep";
#endif
#ifdef SYS_time
    case SYS_time:
        return "time";
#endif
#ifdef SYS_getrandom
    case SYS_getrandom:
        return "getrandom";
#endif
#ifdef SYS_uname
    case SYS_uname:
        return "uname";
#endif
#ifdef SYS_access
    case SYS_access:
        return "access";
#endif
#ifdef SYS_faccessat
    case SYS_faccessat:
        return "faccessat";
#endif
#ifdef SYS_readlink
    case SYS_readlink:
        return "readlink";
#endif
#ifdef SYS_getdents64
    case SYS_getdents64:
        return "getdents64";
#endif
#ifdef SYS_prlimit64
    case SYS_prlimit64:
        return "prlimit64";
#endif
#ifdef SYS_set_tid_address
    case SYS_set_tid_address:
        return "set_tid_address";
#endif
#ifdef SYS_set_robust_list
    case SYS_set_robust_list:
        return "set_robust_list";
#endif
#ifdef SYS_rt_sigreturn
    case SYS_rt_sigreturn:
        return "rt_sigreturn";
#endif
#ifdef SYS_rt_sigaction
    case SYS_rt_sigaction:
        return "rt_sigaction";
#endif
#ifdef SYS_rt_sigprocmask
    case SYS_rt_sigprocmask:
        return "rt_sigprocmask";
#endif
#ifdef SYS_kill
    case SYS_kill:
        return "kill";
#endif
#ifdef SYS_tkill
    case SYS_tkill:
        return "tkill";
#endif
#ifdef SYS_tgkill
    case SYS_tgkill:
        return "tgkill";
#endif
#ifdef SYS_rseq
    case SYS_rseq:
        return "rseq";
#endif
#ifdef SYS_wait4
    case SYS_wait4:
        return "wait4";
#endif
#ifdef SYS_execve
    case SYS_execve:
        return "execve";
#endif
#ifdef SYS_clone
    case SYS_clone:
        return "clone";
#endif
#ifdef SYS_fork
    case SYS_fork:
        return "fork";
#endif
#ifdef SYS_vfork
    case SYS_vfork:
        return "vfork";
#endif
    default:
        return "unknown";
    }
}

struct GuestTimespec {
    i64 tv_sec;
    i64 tv_nsec;
};

struct GuestIOVec {
    u64 base;
    u64 length;
};

struct GuestStat {
    u64 st_dev;
    u64 st_ino;
    u64 st_nlink;
    u32 st_mode;
    u32 st_uid;
    u32 st_gid;
    u32 __pad0;
    u64 st_rdev;
    i64 st_size;
    i64 st_blksize;
    i64 st_blocks;
    i64 st_atime_sec;
    i64 st_atime_nsec;
    i64 st_mtime_sec;
    i64 st_mtime_nsec;
    i64 st_ctime_sec;
    i64 st_ctime_nsec;
    i64 __unused[3];
};

struct GuestUtsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct GuestRLimit64 {
    u64 rlim_cur;
    u64 rlim_max;
};

struct GuestSigAction {
    u64 handler;
    u64 flags;
    u64 restorer;
    u64 mask;
};

struct GuestPollFD {
    i32 fd;
    i16 events;
    i16 revents;
};

struct GuestTimeval {
    i64 tv_sec;
    i64 tv_usec;
};

static_assert(sizeof(GuestTimespec) == 16);
static_assert(sizeof(GuestIOVec) == 16);
static_assert(sizeof(GuestStat) == 144);
static_assert(sizeof(GuestUtsname) == 390);
static_assert(sizeof(GuestRLimit64) == 16);
static_assert(sizeof(GuestSigAction) == 32);
static_assert(sizeof(GuestPollFD) == 8);
static_assert(sizeof(GuestTimeval) == 16);

GuestStat convert_stat(const struct stat& st)
{
    GuestStat out {};
    out.st_dev = static_cast<u64>(st.st_dev);
    out.st_ino = static_cast<u64>(st.st_ino);
    out.st_nlink = static_cast<u64>(st.st_nlink);
    out.st_mode = static_cast<u32>(st.st_mode);
    out.st_uid = static_cast<u32>(st.st_uid);
    out.st_gid = static_cast<u32>(st.st_gid);
    out.st_rdev = static_cast<u64>(st.st_rdev);
    out.st_size = static_cast<i64>(st.st_size);
    out.st_blksize = static_cast<i64>(st.st_blksize);
    out.st_blocks = static_cast<i64>(st.st_blocks);
#if defined(__APPLE__)
    out.st_atime_sec = st.st_atimespec.tv_sec;
    out.st_atime_nsec = st.st_atimespec.tv_nsec;
    out.st_mtime_sec = st.st_mtimespec.tv_sec;
    out.st_mtime_nsec = st.st_mtimespec.tv_nsec;
    out.st_ctime_sec = st.st_ctimespec.tv_sec;
    out.st_ctime_nsec = st.st_ctimespec.tv_nsec;
#else
    out.st_atime_sec = st.st_atim.tv_sec;
    out.st_atime_nsec = st.st_atim.tv_nsec;
    out.st_mtime_sec = st.st_mtim.tv_sec;
    out.st_mtime_nsec = st.st_mtim.tv_nsec;
    out.st_ctime_sec = st.st_ctim.tv_sec;
    out.st_ctime_nsec = st.st_ctim.tv_nsec;
#endif
    return out;
}

int prot_from_linux(u64 prot)
{
    int result = 0;
    if (prot & PROT_READ)
        result |= ProtRead;
    if (prot & PROT_WRITE)
        result |= ProtWrite;
    if (prot & PROT_EXEC)
        result |= ProtExecute;
    return result;
}

void copy_capped(char* destination, const char* source, size_t size)
{
    std::strncpy(destination, source, size - 1);
    destination[size - 1] = '\0';
}

bool guest_range_is_mapped(const SoftMMU& mmu, u64 address, u64 size)
{
    if (size == 0)
        return false;
    for (u64 offset = 0; offset < size; offset += page_size) {
        if (mmu.is_mapped(address + offset, 1))
            return true;
    }
    return mmu.is_mapped(address + size - 1, 1);
}

std::vector<u8> optional_sockaddr_from_guest(const SoftMMU& mmu, u64 address, u64 length)
{
    if (!address || length == 0)
        return {};
    length = std::min<u64>(length, 4096);
    return mmu.copy_buffer_from_guest(address, static_cast<size_t>(length));
}

void copy_sockaddr_to_guest(SoftMMU& mmu, u64 address, u64 length_address, const std::vector<u8>& buffer, socklen_t length)
{
    if (address && length)
        mmu.copy_to_guest(address, buffer.data(), std::min<size_t>(buffer.size(), length));
    if (length_address)
        mmu.write32(length_address, length);
}

void write_guest_fds(Emulator& emulator, u64 address, const int* fds, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        emulator.mmu().write32(address + i * sizeof(i32), static_cast<u32>(fds[i]));
        emulator.register_host_fd(fds[i]);
    }
}

}

u64 LinuxSyscalls::dispatch(Emulator& emulator, u64 number)
{
    auto& cpu = emulator.cpu();
    auto& mmu = emulator.mmu();

    u64 arg1 = cpu.reg(SoftCPU64::RDI);
    u64 arg2 = cpu.reg(SoftCPU64::RSI);
    u64 arg3 = cpu.reg(SoftCPU64::RDX);
    u64 arg4 = cpu.reg(SoftCPU64::R10);
    u64 arg5 = cpu.reg(SoftCPU64::R8);
    u64 arg6 = cpu.reg(SoftCPU64::R9);

    if (emulator.options().trace_syscalls) {
        std::cerr << "syscall " << syscall_name(number) << "(" << number << ")"
                  << " " << hex(arg1) << " " << hex(arg2) << " " << hex(arg3)
                  << " " << hex(arg4) << " " << hex(arg5) << " " << hex(arg6) << "\n";
    }

    switch (number) {
#ifdef SYS_read
    case SYS_read: {
        std::vector<u8> buffer(static_cast<size_t>(arg3));
        auto rc = ::read(static_cast<int>(arg1), buffer.data(), buffer.size());
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, buffer.data(), static_cast<size_t>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_write
    case SYS_write: {
        auto buffer = mmu.copy_buffer_from_guest(arg2, static_cast<size_t>(arg3));
        return syscall_result(::write(static_cast<int>(arg1), buffer.data(), buffer.size()));
    }
#endif

#ifdef SYS_readv
    case SYS_readv: {
        if (arg3 > 1024)
            return syscall_error(EINVAL);
        std::vector<GuestIOVec> guest_iov(static_cast<size_t>(arg3));
        mmu.copy_from_guest(guest_iov.data(), arg2, guest_iov.size() * sizeof(GuestIOVec));

        std::vector<std::vector<u8>> buffers;
        std::vector<iovec> host_iov;
        buffers.reserve(guest_iov.size());
        host_iov.reserve(guest_iov.size());
        for (auto const& entry : guest_iov) {
            buffers.emplace_back(static_cast<size_t>(entry.length));
            host_iov.push_back({ buffers.back().data(), buffers.back().size() });
        }

        auto rc = ::readv(static_cast<int>(arg1), host_iov.data(), static_cast<int>(host_iov.size()));
        if (rc < 0)
            return syscall_error(errno);

        size_t remaining = static_cast<size_t>(rc);
        for (size_t i = 0; i < guest_iov.size() && remaining; ++i) {
            size_t to_copy = std::min<size_t>(remaining, buffers[i].size());
            mmu.copy_to_guest(guest_iov[i].base, buffers[i].data(), to_copy);
            remaining -= to_copy;
        }
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_writev
    case SYS_writev: {
        if (arg3 > 1024)
            return syscall_error(EINVAL);
        std::vector<GuestIOVec> guest_iov(static_cast<size_t>(arg3));
        mmu.copy_from_guest(guest_iov.data(), arg2, guest_iov.size() * sizeof(GuestIOVec));

        std::vector<std::vector<u8>> buffers;
        std::vector<iovec> host_iov;
        buffers.reserve(guest_iov.size());
        host_iov.reserve(guest_iov.size());
        for (auto const& entry : guest_iov) {
            buffers.push_back(mmu.copy_buffer_from_guest(entry.base, static_cast<size_t>(entry.length)));
            host_iov.push_back({ buffers.back().data(), buffers.back().size() });
        }

        return syscall_result(::writev(static_cast<int>(arg1), host_iov.data(), static_cast<int>(host_iov.size())));
    }
#endif

#ifdef SYS_pread64
    case SYS_pread64: {
        std::vector<u8> buffer(static_cast<size_t>(arg3));
        auto rc = ::pread(static_cast<int>(arg1), buffer.data(), buffer.size(), static_cast<off_t>(arg4));
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, buffer.data(), static_cast<size_t>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_pwrite64
    case SYS_pwrite64: {
        auto buffer = mmu.copy_buffer_from_guest(arg2, static_cast<size_t>(arg3));
        return syscall_result(::pwrite(static_cast<int>(arg1), buffer.data(), buffer.size(), static_cast<off_t>(arg4)));
    }
#endif

#ifdef SYS_open
    case SYS_open: {
        auto path = mmu.read_c_string(arg1);
        auto fd = ::open(path.c_str(), static_cast<int>(arg2), static_cast<mode_t>(arg3));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_openat
    case SYS_openat: {
        auto path = mmu.read_c_string(arg2);
        auto fd = ::openat(static_cast<int>(arg1), path.c_str(), static_cast<int>(arg3), static_cast<mode_t>(arg4));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_close
    case SYS_close: {
        int fd = static_cast<int>(arg1);
        auto rc = ::close(fd);
        if (rc < 0)
            return syscall_error(errno);
        emulator.unregister_host_fd(fd);
        return 0;
    }
#endif

#ifdef SYS_dup
    case SYS_dup: {
        auto fd = ::dup(static_cast<int>(arg1));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_dup2
    case SYS_dup2: {
        auto fd = ::dup2(static_cast<int>(arg1), static_cast<int>(arg2));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_dup3
    case SYS_dup3: {
        auto fd = ::dup3(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_pipe
    case SYS_pipe: {
        int fds[2] {};
        if (::pipe(fds) < 0)
            return syscall_error(errno);
        write_guest_fds(emulator, arg1, fds, 2);
        return 0;
    }
#endif

#ifdef SYS_pipe2
    case SYS_pipe2: {
        int fds[2] {};
        if (::pipe2(fds, static_cast<int>(arg2)) < 0)
            return syscall_error(errno);
        write_guest_fds(emulator, arg1, fds, 2);
        return 0;
    }
#endif

#ifdef SYS_fcntl
    case SYS_fcntl: {
        long rc = ::fcntl(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<long>(arg3));
        if (rc < 0)
            return syscall_error(errno);
        if (arg2 == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
            || arg2 == F_DUPFD_CLOEXEC
#endif
        )
            emulator.register_host_fd(static_cast<int>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_lseek
    case SYS_lseek:
        return syscall_result(::lseek(static_cast<int>(arg1), static_cast<off_t>(arg2), static_cast<int>(arg3)));
#endif

#ifdef SYS_stat
    case SYS_stat: {
        auto path = mmu.read_c_string(arg1);
        struct stat st {};
        if (::stat(path.c_str(), &st) < 0)
            return syscall_error(errno);
        auto guest = convert_stat(st);
        mmu.copy_to_guest(arg2, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_lstat
    case SYS_lstat: {
        auto path = mmu.read_c_string(arg1);
        struct stat st {};
        if (::lstat(path.c_str(), &st) < 0)
            return syscall_error(errno);
        auto guest = convert_stat(st);
        mmu.copy_to_guest(arg2, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_fstat
    case SYS_fstat: {
        struct stat st {};
        if (::fstat(static_cast<int>(arg1), &st) < 0)
            return syscall_error(errno);
        auto guest = convert_stat(st);
        mmu.copy_to_guest(arg2, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_newfstatat
    case SYS_newfstatat: {
        std::string path;
        const char* path_ptr = nullptr;
        if (arg2) {
            path = mmu.read_c_string(arg2);
            path_ptr = path.c_str();
        }
        struct stat st {};
        long rc = ::syscall(SYS_newfstatat, static_cast<int>(arg1), path_ptr, &st, static_cast<int>(arg4));
        if (rc < 0)
            return syscall_error(errno);
        auto guest = convert_stat(st);
        mmu.copy_to_guest(arg3, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_mmap
    case SYS_mmap: {
        if (arg2 == 0)
            return syscall_error(EINVAL);
        u64 size = page_align_up(arg2);
        int guest_prot = prot_from_linux(arg3);
        bool fixed = arg4 & MAP_FIXED;
#ifdef MAP_FIXED_NOREPLACE
        bool fixed_noreplace = arg4 & MAP_FIXED_NOREPLACE;
#else
        bool fixed_noreplace = false;
#endif
        bool anonymous = arg4 & MAP_ANONYMOUS;
        u64 address = arg1;
        std::string mapping_name = "[mmap]";
        std::optional<std::string> mapped_path;
        if (!anonymous) {
            mapped_path = emulator.path_for_fd(static_cast<int>(arg5));
            if (mapped_path.has_value())
                mapping_name = mapped_path.value();
        }

        if (fixed || fixed_noreplace) {
            address = page_align_down(address);
            if (fixed_noreplace && guest_range_is_mapped(mmu, address, size))
                return syscall_error(EEXIST);
            mmu.unmap(address, size);
            mmu.map_zeroed(address, size, ProtRead | ProtWrite, mapping_name);
        } else {
            address = mmu.allocate(size, page_size, ProtRead | ProtWrite, mapping_name);
        }

        if (!anonymous) {
            std::vector<u8> file_data(static_cast<size_t>(size));
            auto rc = ::pread(static_cast<int>(arg5), file_data.data(), file_data.size(), static_cast<off_t>(arg6));
            if (rc < 0) {
                mmu.unmap(address, size);
                return syscall_error(errno);
            }
            mmu.copy_to_guest(address, file_data.data(), static_cast<size_t>(rc));
            if (arg6 == 0 && mapped_path.has_value())
                emulator.register_mapped_file(mapped_path.value(), address);
        }
        mmu.protect(address, size, guest_prot);
        return address;
    }
#endif

#ifdef SYS_munmap
    case SYS_munmap:
        mmu.unmap(arg1, arg2);
        return 0;
#endif

#ifdef SYS_mprotect
    case SYS_mprotect:
        mmu.protect(arg1, arg2, prot_from_linux(arg3));
        return 0;
#endif

#ifdef SYS_brk
    case SYS_brk:
        return emulator.set_brk(arg1);
#endif

#ifdef SYS_arch_prctl
    case SYS_arch_prctl:
        switch (arg1) {
#ifdef ARCH_SET_FS
        case ARCH_SET_FS:
            cpu.set_fs_base(arg2);
            return 0;
        case ARCH_GET_FS:
            mmu.write64(arg2, cpu.fs_base());
            return 0;
        case ARCH_SET_GS:
            cpu.set_gs_base(arg2);
            return 0;
        case ARCH_GET_GS:
            mmu.write64(arg2, cpu.gs_base());
            return 0;
#endif
        default:
            return syscall_error(EINVAL);
        }
#endif

#ifdef SYS_exit
    case SYS_exit:
        throw GuestExit(static_cast<int>(arg1));
#endif

#ifdef SYS_exit_group
    case SYS_exit_group:
        throw GuestExit(static_cast<int>(arg1));
#endif

#ifdef SYS_getpid
    case SYS_getpid:
        return static_cast<u64>(::getpid());
#endif

#ifdef SYS_gettid
    case SYS_gettid:
        return syscall_result(::syscall(SYS_gettid));
#endif

#ifdef SYS_getppid
    case SYS_getppid:
        return static_cast<u64>(::getppid());
#endif

#ifdef SYS_getpgid
    case SYS_getpgid: {
        pid_t pid = static_cast<pid_t>(arg1);
        return syscall_result(::getpgid(pid));
    }
#endif

#ifdef SYS_getpgrp
    case SYS_getpgrp:
        return static_cast<u64>(::getpgrp());
#endif

#ifdef SYS_getuid
    case SYS_getuid:
        return static_cast<u64>(::getuid());
#endif

#ifdef SYS_geteuid
    case SYS_geteuid:
        return static_cast<u64>(::geteuid());
#endif

#ifdef SYS_getgid
    case SYS_getgid:
        return static_cast<u64>(::getgid());
#endif

#ifdef SYS_getegid
    case SYS_getegid:
        return static_cast<u64>(::getegid());
#endif

#ifdef SYS_getcwd
    case SYS_getcwd: {
        std::vector<char> buffer(static_cast<size_t>(arg2));
        if (!::getcwd(buffer.data(), buffer.size()))
            return syscall_error(errno);
        size_t length = std::strlen(buffer.data()) + 1;
        mmu.copy_to_guest(arg1, buffer.data(), length);
        return length;
    }
#endif

#ifdef SYS_ioctl
    case SYS_ioctl: {
        if (arg3 == 0)
            return syscall_result(::ioctl(static_cast<int>(arg1), static_cast<unsigned long>(arg2), 0));
        std::array<u8, 256> scratch {};
        if (mmu.is_mapped(arg3, 1)) {
            size_t copy_size = std::min<size_t>(scratch.size(), 128);
            try {
                mmu.copy_from_guest(scratch.data(), arg3, copy_size);
            } catch (const EmulatorError&) {
            }
        }
        long rc = ::ioctl(static_cast<int>(arg1), static_cast<unsigned long>(arg2), scratch.data());
        if (rc < 0)
            return syscall_error(errno);
        try {
            mmu.copy_to_guest(arg3, scratch.data(), scratch.size());
        } catch (const EmulatorError&) {
        }
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_poll
    case SYS_poll: {
        if (arg2 > 4096)
            return syscall_error(EINVAL);
        std::vector<GuestPollFD> guest_fds(static_cast<size_t>(arg2));
        std::vector<pollfd> host_fds(static_cast<size_t>(arg2));
        if (arg2)
            mmu.copy_from_guest(guest_fds.data(), arg1, guest_fds.size() * sizeof(GuestPollFD));
        for (size_t i = 0; i < guest_fds.size(); ++i)
            host_fds[i] = { guest_fds[i].fd, guest_fds[i].events, guest_fds[i].revents };
        auto rc = ::poll(host_fds.data(), static_cast<nfds_t>(host_fds.size()), static_cast<int>(arg3));
        if (rc < 0)
            return syscall_error(errno);
        for (size_t i = 0; i < guest_fds.size(); ++i)
            guest_fds[i].revents = host_fds[i].revents;
        if (arg2)
            mmu.copy_to_guest(arg1, guest_fds.data(), guest_fds.size() * sizeof(GuestPollFD));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_ppoll
    case SYS_ppoll: {
        if (arg2 > 4096)
            return syscall_error(EINVAL);
        std::vector<GuestPollFD> guest_fds(static_cast<size_t>(arg2));
        std::vector<pollfd> host_fds(static_cast<size_t>(arg2));
        if (arg2)
            mmu.copy_from_guest(guest_fds.data(), arg1, guest_fds.size() * sizeof(GuestPollFD));
        for (size_t i = 0; i < guest_fds.size(); ++i)
            host_fds[i] = { guest_fds[i].fd, guest_fds[i].events, guest_fds[i].revents };
        struct timespec timeout {};
        struct timespec* timeout_ptr = nullptr;
        if (arg3) {
            GuestTimespec guest {};
            mmu.copy_from_guest(&guest, arg3, sizeof(guest));
            timeout = { static_cast<time_t>(guest.tv_sec), static_cast<long>(guest.tv_nsec) };
            timeout_ptr = &timeout;
        }
        long rc = ::syscall(SYS_ppoll, host_fds.data(), static_cast<nfds_t>(host_fds.size()), timeout_ptr, nullptr, 0);
        if (rc < 0)
            return syscall_error(errno);
        for (size_t i = 0; i < guest_fds.size(); ++i)
            guest_fds[i].revents = host_fds[i].revents;
        if (arg2)
            mmu.copy_to_guest(arg1, guest_fds.data(), guest_fds.size() * sizeof(GuestPollFD));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_select
    case SYS_select: {
        std::array<u8, sizeof(fd_set)> readfds {};
        std::array<u8, sizeof(fd_set)> writefds {};
        std::array<u8, sizeof(fd_set)> exceptfds {};
        fd_set* read_ptr = nullptr;
        fd_set* write_ptr = nullptr;
        fd_set* except_ptr = nullptr;
        if (arg2) {
            mmu.copy_from_guest(readfds.data(), arg2, readfds.size());
            read_ptr = reinterpret_cast<fd_set*>(readfds.data());
        }
        if (arg3) {
            mmu.copy_from_guest(writefds.data(), arg3, writefds.size());
            write_ptr = reinterpret_cast<fd_set*>(writefds.data());
        }
        if (arg4) {
            mmu.copy_from_guest(exceptfds.data(), arg4, exceptfds.size());
            except_ptr = reinterpret_cast<fd_set*>(exceptfds.data());
        }
        struct timeval timeout {};
        struct timeval* timeout_ptr = nullptr;
        if (arg5) {
            GuestTimeval guest {};
            mmu.copy_from_guest(&guest, arg5, sizeof(guest));
            timeout = { static_cast<time_t>(guest.tv_sec), static_cast<suseconds_t>(guest.tv_usec) };
            timeout_ptr = &timeout;
        }
        auto rc = ::select(static_cast<int>(arg1), read_ptr, write_ptr, except_ptr, timeout_ptr);
        if (rc < 0)
            return syscall_error(errno);
        if (arg2)
            mmu.copy_to_guest(arg2, readfds.data(), readfds.size());
        if (arg3)
            mmu.copy_to_guest(arg3, writefds.data(), writefds.size());
        if (arg4)
            mmu.copy_to_guest(arg4, exceptfds.data(), exceptfds.size());
        if (arg5) {
            GuestTimeval guest { static_cast<i64>(timeout.tv_sec), static_cast<i64>(timeout.tv_usec) };
            mmu.copy_to_guest(arg5, &guest, sizeof(guest));
        }
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_pselect6
    case SYS_pselect6: {
        std::array<u8, sizeof(fd_set)> readfds {};
        std::array<u8, sizeof(fd_set)> writefds {};
        std::array<u8, sizeof(fd_set)> exceptfds {};
        fd_set* read_ptr = nullptr;
        fd_set* write_ptr = nullptr;
        fd_set* except_ptr = nullptr;
        if (arg2) {
            mmu.copy_from_guest(readfds.data(), arg2, readfds.size());
            read_ptr = reinterpret_cast<fd_set*>(readfds.data());
        }
        if (arg3) {
            mmu.copy_from_guest(writefds.data(), arg3, writefds.size());
            write_ptr = reinterpret_cast<fd_set*>(writefds.data());
        }
        if (arg4) {
            mmu.copy_from_guest(exceptfds.data(), arg4, exceptfds.size());
            except_ptr = reinterpret_cast<fd_set*>(exceptfds.data());
        }
        struct timespec timeout {};
        struct timespec* timeout_ptr = nullptr;
        if (arg5) {
            GuestTimespec guest {};
            mmu.copy_from_guest(&guest, arg5, sizeof(guest));
            timeout = { static_cast<time_t>(guest.tv_sec), static_cast<long>(guest.tv_nsec) };
            timeout_ptr = &timeout;
        }
        long rc = ::syscall(SYS_pselect6, static_cast<int>(arg1), read_ptr, write_ptr, except_ptr, timeout_ptr, nullptr);
        if (rc < 0)
            return syscall_error(errno);
        if (arg2)
            mmu.copy_to_guest(arg2, readfds.data(), readfds.size());
        if (arg3)
            mmu.copy_to_guest(arg3, writefds.data(), writefds.size());
        if (arg4)
            mmu.copy_to_guest(arg4, exceptfds.data(), exceptfds.size());
        if (arg5) {
            GuestTimespec guest { static_cast<i64>(timeout.tv_sec), static_cast<i64>(timeout.tv_nsec) };
            mmu.copy_to_guest(arg5, &guest, sizeof(guest));
        }
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_epoll_create1
    case SYS_epoll_create1: {
        int fd = ::epoll_create1(static_cast<int>(arg1));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_epoll_ctl
    case SYS_epoll_ctl: {
        std::array<u8, sizeof(epoll_event)> event {};
        void* event_ptr = nullptr;
        if (arg4) {
            mmu.copy_from_guest(event.data(), arg4, event.size());
            event_ptr = event.data();
        }
        return syscall_result(::syscall(SYS_epoll_ctl, static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), event_ptr));
    }
#endif

#ifdef SYS_epoll_wait
    case SYS_epoll_wait: {
        std::vector<u8> events(static_cast<size_t>(arg3) * sizeof(epoll_event));
        long rc = ::syscall(SYS_epoll_wait, static_cast<int>(arg1), events.data(), static_cast<int>(arg3), static_cast<int>(arg4));
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, events.data(), static_cast<size_t>(rc) * sizeof(epoll_event));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_epoll_pwait
    case SYS_epoll_pwait: {
        std::vector<u8> events(static_cast<size_t>(arg3) * sizeof(epoll_event));
        long rc = ::syscall(SYS_epoll_pwait, static_cast<int>(arg1), events.data(), static_cast<int>(arg3), static_cast<int>(arg4), nullptr, 0);
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, events.data(), static_cast<size_t>(rc) * sizeof(epoll_event));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_socket
    case SYS_socket: {
        int fd = ::socket(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_socketpair
    case SYS_socketpair: {
        int fds[2] {};
        if (::socketpair(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), fds) < 0)
            return syscall_error(errno);
        write_guest_fds(emulator, arg4, fds, 2);
        return 0;
    }
#endif

#ifdef SYS_bind
    case SYS_bind: {
        auto address = optional_sockaddr_from_guest(mmu, arg2, arg3);
        return syscall_result(::bind(static_cast<int>(arg1), reinterpret_cast<const sockaddr*>(address.data()), static_cast<socklen_t>(address.size())));
    }
#endif

#ifdef SYS_listen
    case SYS_listen:
        return syscall_result(::listen(static_cast<int>(arg1), static_cast<int>(arg2)));
#endif

#ifdef SYS_accept
    case SYS_accept: {
        socklen_t length = 0;
        if (arg3)
            length = mmu.read32(arg3);
        std::vector<u8> address(length);
        int fd = ::accept(static_cast<int>(arg1), arg2 ? reinterpret_cast<sockaddr*>(address.data()) : nullptr, arg3 ? &length : nullptr);
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        copy_sockaddr_to_guest(mmu, arg2, arg3, address, length);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_accept4
    case SYS_accept4: {
        socklen_t length = 0;
        if (arg3)
            length = mmu.read32(arg3);
        std::vector<u8> address(length);
        int fd = ::accept4(static_cast<int>(arg1), arg2 ? reinterpret_cast<sockaddr*>(address.data()) : nullptr, arg3 ? &length : nullptr, static_cast<int>(arg4));
        if (fd < 0)
            return syscall_error(errno);
        emulator.register_host_fd(fd);
        copy_sockaddr_to_guest(mmu, arg2, arg3, address, length);
        return static_cast<u64>(fd);
    }
#endif

#ifdef SYS_connect
    case SYS_connect: {
        auto address = optional_sockaddr_from_guest(mmu, arg2, arg3);
        return syscall_result(::connect(static_cast<int>(arg1), reinterpret_cast<const sockaddr*>(address.data()), static_cast<socklen_t>(address.size())));
    }
#endif

#ifdef SYS_getsockname
    case SYS_getsockname: {
        socklen_t length = arg3 ? mmu.read32(arg3) : 0;
        std::vector<u8> address(length);
        auto rc = ::getsockname(static_cast<int>(arg1), arg2 ? reinterpret_cast<sockaddr*>(address.data()) : nullptr, arg3 ? &length : nullptr);
        if (rc < 0)
            return syscall_error(errno);
        copy_sockaddr_to_guest(mmu, arg2, arg3, address, length);
        return 0;
    }
#endif

#ifdef SYS_getpeername
    case SYS_getpeername: {
        socklen_t length = arg3 ? mmu.read32(arg3) : 0;
        std::vector<u8> address(length);
        auto rc = ::getpeername(static_cast<int>(arg1), arg2 ? reinterpret_cast<sockaddr*>(address.data()) : nullptr, arg3 ? &length : nullptr);
        if (rc < 0)
            return syscall_error(errno);
        copy_sockaddr_to_guest(mmu, arg2, arg3, address, length);
        return 0;
    }
#endif

#ifdef SYS_setsockopt
    case SYS_setsockopt: {
        auto value = arg4 ? mmu.copy_buffer_from_guest(arg4, static_cast<size_t>(arg5)) : std::vector<u8> {};
        return syscall_result(::setsockopt(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), value.data(), static_cast<socklen_t>(value.size())));
    }
#endif

#ifdef SYS_getsockopt
    case SYS_getsockopt: {
        socklen_t length = arg5 ? mmu.read32(arg5) : 0;
        std::vector<u8> value(length);
        auto rc = ::getsockopt(static_cast<int>(arg1), static_cast<int>(arg2), static_cast<int>(arg3), value.data(), &length);
        if (rc < 0)
            return syscall_error(errno);
        if (arg4)
            mmu.copy_to_guest(arg4, value.data(), std::min<size_t>(value.size(), length));
        if (arg5)
            mmu.write32(arg5, length);
        return 0;
    }
#endif

#ifdef SYS_sendto
    case SYS_sendto: {
        auto buffer = mmu.copy_buffer_from_guest(arg2, static_cast<size_t>(arg3));
        auto address = optional_sockaddr_from_guest(mmu, arg5, arg6);
        const sockaddr* address_ptr = address.empty() ? nullptr : reinterpret_cast<const sockaddr*>(address.data());
        return syscall_result(::sendto(static_cast<int>(arg1), buffer.data(), buffer.size(), static_cast<int>(arg4), address_ptr, static_cast<socklen_t>(address.size())));
    }
#endif

#ifdef SYS_recvfrom
    case SYS_recvfrom: {
        std::vector<u8> buffer(static_cast<size_t>(arg3));
        socklen_t length = arg6 ? mmu.read32(arg6) : 0;
        std::vector<u8> address(length);
        auto rc = ::recvfrom(static_cast<int>(arg1), buffer.data(), buffer.size(), static_cast<int>(arg4), arg5 ? reinterpret_cast<sockaddr*>(address.data()) : nullptr, arg6 ? &length : nullptr);
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, buffer.data(), static_cast<size_t>(rc));
        copy_sockaddr_to_guest(mmu, arg5, arg6, address, length);
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_shutdown
    case SYS_shutdown:
        return syscall_result(::shutdown(static_cast<int>(arg1), static_cast<int>(arg2)));
#endif

#ifdef SYS_clock_gettime
    case SYS_clock_gettime: {
        struct timespec ts {};
        if (::clock_gettime(static_cast<clockid_t>(arg1), &ts) < 0)
            return syscall_error(errno);
        GuestTimespec guest { static_cast<i64>(ts.tv_sec), static_cast<i64>(ts.tv_nsec) };
        mmu.copy_to_guest(arg2, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_clock_nanosleep
    case SYS_clock_nanosleep: {
        GuestTimespec guest_request {};
        mmu.copy_from_guest(&guest_request, arg3, sizeof(guest_request));
        struct timespec request { static_cast<time_t>(guest_request.tv_sec), static_cast<long>(guest_request.tv_nsec) };
        struct timespec remain {};
        auto rc = ::clock_nanosleep(static_cast<clockid_t>(arg1), static_cast<int>(arg2), &request, arg4 ? &remain : nullptr);
        if (rc != 0)
            return syscall_error(rc);
        if (arg4) {
            GuestTimespec guest_remain { static_cast<i64>(remain.tv_sec), static_cast<i64>(remain.tv_nsec) };
            mmu.copy_to_guest(arg4, &guest_remain, sizeof(guest_remain));
        }
        return 0;
    }
#endif

#ifdef SYS_gettimeofday
    case SYS_gettimeofday: {
        struct timeval tv {};
        if (::gettimeofday(&tv, nullptr) < 0)
            return syscall_error(errno);
        if (arg1) {
            GuestTimeval guest { static_cast<i64>(tv.tv_sec), static_cast<i64>(tv.tv_usec) };
            mmu.copy_to_guest(arg1, &guest, sizeof(guest));
        }
        return 0;
    }
#endif

#ifdef SYS_nanosleep
    case SYS_nanosleep: {
        GuestTimespec guest_request {};
        mmu.copy_from_guest(&guest_request, arg1, sizeof(guest_request));
        struct timespec request { static_cast<time_t>(guest_request.tv_sec), static_cast<long>(guest_request.tv_nsec) };
        struct timespec remain {};
        auto rc = ::nanosleep(&request, arg2 ? &remain : nullptr);
        if (rc < 0)
            return syscall_error(errno);
        if (arg2) {
            GuestTimespec guest_remain { static_cast<i64>(remain.tv_sec), static_cast<i64>(remain.tv_nsec) };
            mmu.copy_to_guest(arg2, &guest_remain, sizeof(guest_remain));
        }
        return 0;
    }
#endif

#ifdef SYS_time
    case SYS_time: {
        auto now = ::time(nullptr);
        if (now == static_cast<time_t>(-1))
            return syscall_error(errno);
        if (arg1)
            mmu.write64(arg1, static_cast<u64>(now));
        return static_cast<u64>(now);
    }
#endif

#ifdef SYS_getrandom
    case SYS_getrandom: {
        std::vector<u8> buffer(static_cast<size_t>(arg2));
        long rc = ::syscall(SYS_getrandom, buffer.data(), buffer.size(), static_cast<unsigned int>(arg3));
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg1, buffer.data(), static_cast<size_t>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_uname
    case SYS_uname: {
        struct utsname host {};
        if (::uname(&host) < 0)
            return syscall_error(errno);
        GuestUtsname guest {};
        copy_capped(guest.sysname, host.sysname, sizeof(guest.sysname));
        copy_capped(guest.nodename, host.nodename, sizeof(guest.nodename));
        copy_capped(guest.release, host.release, sizeof(guest.release));
        copy_capped(guest.version, host.version, sizeof(guest.version));
        copy_capped(guest.machine, "x86_64", sizeof(guest.machine));
#ifdef _GNU_SOURCE
        copy_capped(guest.domainname, host.domainname, sizeof(guest.domainname));
#endif
        mmu.copy_to_guest(arg1, &guest, sizeof(guest));
        return 0;
    }
#endif

#ifdef SYS_access
    case SYS_access: {
        auto path = mmu.read_c_string(arg1);
        return syscall_result(::access(path.c_str(), static_cast<int>(arg2)));
    }
#endif

#ifdef SYS_faccessat
    case SYS_faccessat: {
        auto path = mmu.read_c_string(arg2);
        return syscall_result(::faccessat(static_cast<int>(arg1), path.c_str(), static_cast<int>(arg3), static_cast<int>(arg4)));
    }
#endif

#ifdef SYS_readlink
    case SYS_readlink: {
        auto path = mmu.read_c_string(arg1);
        std::vector<char> buffer(static_cast<size_t>(arg3));
        auto rc = ::readlink(path.c_str(), buffer.data(), buffer.size());
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, buffer.data(), static_cast<size_t>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_getdents64
    case SYS_getdents64: {
        std::vector<u8> buffer(static_cast<size_t>(arg3));
        long rc = ::syscall(SYS_getdents64, static_cast<int>(arg1), buffer.data(), buffer.size());
        if (rc < 0)
            return syscall_error(errno);
        mmu.copy_to_guest(arg2, buffer.data(), static_cast<size_t>(rc));
        return static_cast<u64>(rc);
    }
#endif

#ifdef SYS_prlimit64
    case SYS_prlimit64: {
        struct rlimit new_limit {};
        struct rlimit old_limit {};
        struct rlimit* new_limit_ptr = nullptr;
        struct rlimit* old_limit_ptr = arg4 ? &old_limit : nullptr;
        if (arg3) {
            GuestRLimit64 guest {};
            mmu.copy_from_guest(&guest, arg3, sizeof(guest));
            new_limit.rlim_cur = static_cast<rlim_t>(guest.rlim_cur);
            new_limit.rlim_max = static_cast<rlim_t>(guest.rlim_max);
            new_limit_ptr = &new_limit;
        }
        long rc = ::syscall(SYS_prlimit64, static_cast<pid_t>(arg1), static_cast<int>(arg2), new_limit_ptr, old_limit_ptr);
        if (rc < 0)
            return syscall_error(errno);
        if (arg4) {
            GuestRLimit64 guest { static_cast<u64>(old_limit.rlim_cur), static_cast<u64>(old_limit.rlim_max) };
            mmu.copy_to_guest(arg4, &guest, sizeof(guest));
        }
        return 0;
    }
#endif

#ifdef SYS_set_tid_address
    case SYS_set_tid_address:
#ifdef SYS_gettid
        return syscall_result(::syscall(SYS_gettid));
#else
        return static_cast<u64>(::getpid());
#endif
#endif

#ifdef SYS_set_robust_list
    case SYS_set_robust_list:
        return 0;
#endif

#ifdef SYS_rt_sigreturn
    case SYS_rt_sigreturn:
        return emulator.handle_sigreturn();
#endif

#ifdef SYS_rt_sigaction
    case SYS_rt_sigaction: {
        if (arg4 != 8)
            return syscall_error(EINVAL);
        GuestSigAction action {};
        if (arg2)
            mmu.copy_from_guest(&action, arg2, sizeof(action));
        int rc = emulator.set_signal_action(static_cast<int>(arg1), arg2 != 0, action.handler, action.flags, action.restorer, action.mask, arg3);
        if (rc < 0)
            return static_cast<u64>(static_cast<i64>(rc));
        return 0;
    }
#endif

#ifdef SYS_rt_sigprocmask
    case SYS_rt_sigprocmask: {
        if (arg4 != 8)
            return syscall_error(EINVAL);
        int rc = emulator.set_signal_mask(static_cast<int>(arg1), arg2, arg3);
        if (rc < 0)
            return static_cast<u64>(static_cast<i64>(rc));
        return 0;
    }
#endif

#ifdef SYS_kill
    case SYS_kill: {
        if (arg1 != 0 && static_cast<pid_t>(arg1) != ::getpid())
            return syscall_error(ESRCH);
        if (arg2 == 0)
            return 0;
        int rc = emulator.deliver_signal(static_cast<int>(arg2));
        if (rc < 0)
            return static_cast<u64>(static_cast<i64>(rc));
        return 0;
    }
#endif

#ifdef SYS_tkill
    case SYS_tkill: {
        if (static_cast<pid_t>(arg1) != static_cast<pid_t>(::syscall(SYS_gettid)))
            return syscall_error(ESRCH);
        if (arg2 == 0)
            return 0;
        int rc = emulator.deliver_signal(static_cast<int>(arg2));
        if (rc < 0)
            return static_cast<u64>(static_cast<i64>(rc));
        return 0;
    }
#endif

#ifdef SYS_tgkill
    case SYS_tgkill: {
        if (static_cast<pid_t>(arg1) != ::getpid() || static_cast<pid_t>(arg2) != static_cast<pid_t>(::syscall(SYS_gettid)))
            return syscall_error(ESRCH);
        if (arg3 == 0)
            return 0;
        int rc = emulator.deliver_signal(static_cast<int>(arg3));
        if (rc < 0)
            return static_cast<u64>(static_cast<i64>(rc));
        return 0;
    }
#endif

#ifdef SYS_wait4
    case SYS_wait4:
        return syscall_error(ECHILD);
#endif

#ifdef SYS_execve
    case SYS_execve:
        return syscall_error(ENOSYS);
#endif

#ifdef SYS_clone
    case SYS_clone:
        return syscall_error(ENOSYS);
#endif

#ifdef SYS_fork
    case SYS_fork:
        return syscall_error(ENOSYS);
#endif

#ifdef SYS_vfork
    case SYS_vfork:
        return syscall_error(ENOSYS);
#endif

#ifdef SYS_futex
    case SYS_futex: {
        int futex_op = static_cast<int>(arg2) & 0x7f;
        if (futex_op == FUTEX_WAKE)
            return 0;
        if (futex_op == FUTEX_WAIT)
            return syscall_error(EAGAIN);
        return syscall_error(ENOSYS);
    }
#endif

#ifdef SYS_rseq
    case SYS_rseq:
        return syscall_error(ENOSYS);
#endif

    default:
        throw EmulatorError("unimplemented syscall " + std::to_string(number) + " (" + syscall_name(number) + ")");
    }
}

}
