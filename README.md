# LinuxUserspaceEmulator

LinuxUserspaceEmulator is a small experimental Linux x86_64 userspace emulator.
It loads ELF64 guest programs, interprets x86_64 instructions in software, keeps
a separate guest address space, and translates guest Linux syscalls to host
Linux syscalls.

The project is inspired by the architecture of SerenityOS UserspaceEmulator, but
it is not a port of SerenityOS code.

## Status

This is a learning and research project, not a production sandbox.

Currently supported:

- static Linux x86_64 ELF programs
- simple dynamically linked glibc programs
- basic virtual memory, `brk`, `mmap`, and file-backed mappings
- common file, time, polling, socket, and signal syscalls
- basic guest signal handling and host signal forwarding
- symbolic guest backtraces for loaded ELF images
- basic byte-level shadow memory for initialized guest memory tracking

Known limitations:

- incomplete x86_64 instruction coverage
- no thread or process model for `clone`, `fork`, or `execve`
- no full POSIX signal semantics
- no full CPU taint propagation, malloc tracing, or leak detection
- no security isolation guarantee

## Build

Linux is the intended host platform.

```sh
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

## Run

```sh
./build/LinuxUserspaceEmulator [options] <program> [args...]
```

Useful options:

```sh
./build/LinuxUserspaceEmulator --help
./build/LinuxUserspaceEmulator --trace-syscalls ./guest-program
./build/LinuxUserspaceEmulator --backtrace-on-exit ./guest-program
```

Example:

```sh
cc -O0 -o /tmp/lue-hello tests/hello-c.c
./build/LinuxUserspaceEmulator /tmp/lue-hello
```

Expected output:

```text
hello from C guest
```

## Tests

```sh
bash tests/run-smoke.sh
```

The smoke suite builds small guest programs and checks static ELF loading,
dynamic glibc startup, arguments and environment, file I/O, `mmap`/`brk`, signal
delivery, host signal forwarding, syscall coverage, TLS basics, and symbolic
backtraces.

## Notes

Unsupported guest instructions or syscalls stop the emulator with the guest RIP,
opcode bytes, registers, a symbolic backtrace when available, and mapped memory
regions. This makes the next missing piece visible and keeps development
incremental.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
