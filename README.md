# LinuxUserspaceEmulator

Standalone Linux x86_64 userspace emulator inspired by SerenityOS
`UserspaceEmulator`.

This project intentionally does not use Unicorn, QEMU, ptrace, or native
execution of the guest. It has:

- a custom ELF64 program loader,
- a guest virtual address space (`SoftMMU`),
- a custom x86_64 instruction interpreter (`SoftCPU64`), and
- a Linux x86_64 syscall translation layer.

## Build

This project currently targets Linux hosts.

```sh
cmake -S . -B build
cmake --build build -j
```

If you want to keep build artifacts outside the source tree, choose any Linux
filesystem path for the build directory:

```sh
cmake -S . -B /tmp/lue-build
cmake --build /tmp/lue-build -j
```

## Run

```sh
./build/LinuxUserspaceEmulator [--trace] [--trace-syscalls] <program> [args...]
```

With the `/tmp` build directory:

```sh
/tmp/lue-build/LinuxUserspaceEmulator <program> [args...]
```

## Current Scope

The first milestone is static, non-threaded command-line programs. A tiny
hand-written static ELF that uses only `syscall` for `write` and `exit` is the
best first smoke test.

Dynamic ELF files with `PT_INTERP` are mapped and receive Linux-style auxv
entries, but real dynamic-linker execution will expose more x86_64/SSE/TLS
instructions that need to be added incrementally.

Unsupported instructions and syscalls stop with RIP, opcode bytes, registers,
and mapped regions so the next missing piece is visible.

## Minimal Smoke Program

```asm
.global _start
.section .text
_start:
    mov $1, %rax
    mov $1, %rdi
    lea message(%rip), %rsi
    mov $message_end-message, %rdx
    syscall

    mov $60, %rax
    xor %rdi, %rdi
    syscall

.section .rodata
message:
    .ascii "hello from guest\n"
message_end:
```

Build it on Linux with:

```sh
cc -nostdlib -static -o hello-static hello-static.S
./build/LinuxUserspaceEmulator --trace-syscalls ./hello-static
```

## Smoke Tests

```sh
bash tests/run-smoke.sh
```

The script builds the emulator in `build-smoke` by default, compiles static
guest test programs, and verifies:

- `hello-static`
- `hello-c`
- `args-env`
- `cat-static`
- `mmap-brk`
- `fs-tls`
