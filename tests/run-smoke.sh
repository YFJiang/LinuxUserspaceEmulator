#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${LUE_BUILD_DIR:-"$repo_dir/build-smoke"}"

cmake -S "$repo_dir" -B "$build_dir" >/dev/null
cmake --build "$build_dir" -j"$(nproc)"

cc -nostdlib -static -o /tmp/lue-hello-static "$repo_dir/tests/hello-static.S"
cc -O0 -o /tmp/lue-hello-dyn "$repo_dir/tests/hello-c.c"
cc -O0 -fno-omit-frame-pointer -o /tmp/lue-symbol-backtrace "$repo_dir/tests/symbol-backtrace.c"
cc -static -O0 -o /tmp/lue-hello-c "$repo_dir/tests/hello-c.c"
cc -static -O0 -o /tmp/lue-args-env "$repo_dir/tests/args-env.c"
cc -static -O0 -o /tmp/lue-cat-static "$repo_dir/tests/cat-static.c"
cc -static -O0 -o /tmp/lue-mmap-brk "$repo_dir/tests/mmap-brk.c"
cc -static -O0 -o /tmp/lue-syscall-coverage "$repo_dir/tests/syscall-coverage.c"
cc -static -O0 -o /tmp/lue-region-types "$repo_dir/tests/region-types.c"
cc -static -O0 -o /tmp/lue-region-dump "$repo_dir/tests/region-dump.c"
cc -static -O0 -o /tmp/lue-shadow-memory "$repo_dir/tests/shadow-memory.c"
cc -O0 -o /tmp/lue-signal-basic "$repo_dir/tests/signal-basic.c"
cc -O0 -o /tmp/lue-host-signal "$repo_dir/tests/host-signal.c"
cc -nostdlib -static -o /tmp/lue-fs-tls "$repo_dir/tests/fs-tls.S"

emulator="$build_dir/LinuxUserspaceEmulator"

run_and_check() {
    local name="$1"
    local expected="$2"
    shift 2

    local output
    output="$("$@")"
    if [[ "$output" != "$expected" ]]; then
        printf 'FAIL %s\nexpected:\n%s\nactual:\n%s\n' "$name" "$expected" "$output" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_and_check_failure_contains() {
    local name="$1"
    shift

    local output status
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e

    if [[ "$status" == 0 ]]; then
        printf 'FAIL %s\nexpected non-zero exit\nactual output:\n%s\n' "$name" "$output" >&2
        return 1
    fi

    if [[ "$output" != *"boom+"* || "$output" != *"main+"* || "$output" != *"[libc.so.6]"* ]]; then
        printf 'FAIL %s\nexpected symbolic backtrace with boom, main, and libc\nactual output:\n%s\n' "$name" "$output" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_and_check_stdout_and_stderr_contains() {
    local name="$1"
    local expected_stdout="$2"
    shift 2

    local stdout_file stderr_file status stdout stderr
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"
    set +e
    "$@" >"$stdout_file" 2>"$stderr_file"
    status=$?
    set -e
    stdout="$(cat "$stdout_file")"
    stderr="$(cat "$stderr_file")"
    rm -f "$stdout_file" "$stderr_file"

    if [[ "$status" != 0 || "$stdout" != "$expected_stdout" || "$stderr" != *"guest exit backtrace"* || "$stderr" != *"main+"* || "$stderr" != *"[libc.so.6]"* ]]; then
        printf 'FAIL %s\nstatus: %s\nexpected stdout:\n%s\nactual stdout:\n%s\nactual stderr:\n%s\n' "$name" "$status" "$expected_stdout" "$stdout" "$stderr" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_and_check_contains() {
    local name="$1"
    local expected="$2"
    shift 2

    local output
    output="$("$@" 2>&1)"
    if [[ "$output" != *"$expected"* ]]; then
        printf 'FAIL %s\nexpected output containing:\n%s\nactual output:\n%s\n' "$name" "$expected" "$output" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_and_check_failure_output_contains() {
    local name="$1"
    local expected="$2"
    shift 2

    local output status
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e

    if [[ "$status" == 0 || "$output" != *"$expected"* ]]; then
        printf 'FAIL %s\nstatus: %s\nexpected failing output containing:\n%s\nactual output:\n%s\n' "$name" "$status" "$expected" "$output" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_and_check_host_signal() {
    local name="$1"
    local stdout_file stderr_file pid status output
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"

    "$emulator" /tmp/lue-host-signal >"$stdout_file" 2>"$stderr_file" &
    pid=$!

    for _ in {1..50}; do
        if grep -q "ready" "$stdout_file"; then
            break
        fi
        sleep 0.1
    done

    if ! grep -q "ready" "$stdout_file"; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        printf 'FAIL %s\nhost-signal guest did not become ready\nstderr:\n%s\n' "$name" "$(cat "$stderr_file")" >&2
        rm -f "$stdout_file" "$stderr_file"
        return 1
    fi

    kill -INT "$pid"
    wait "$pid"
    status=$?
    output="$(cat "$stdout_file")"
    if [[ "$status" != 0 || "$output" != $'ready\nhandled' ]]; then
        printf 'FAIL %s\nstatus: %s\nexpected stdout:\n%s\nactual stdout:\n%s\nstderr:\n%s\n' "$name" "$status" $'ready\nhandled' "$output" "$(cat "$stderr_file")" >&2
        rm -f "$stdout_file" "$stderr_file"
        return 1
    fi
    rm -f "$stdout_file" "$stderr_file"
    printf 'PASS %s\n' "$name"
}

run_and_check_contains help "--backtrace-on-exit" "$emulator" --help
run_and_check hello-static "hello from guest" "$emulator" /tmp/lue-hello-static
run_and_check hello-dyn "hello from C guest" "$emulator" /tmp/lue-hello-dyn
run_and_check_stdout_and_stderr_contains hello-dyn-exit-backtrace "hello from C guest" "$emulator" --backtrace-on-exit /tmp/lue-hello-dyn
run_and_check_failure_contains symbol-backtrace "$emulator" /tmp/lue-symbol-backtrace
run_and_check hello-c "hello from C guest" "$emulator" /tmp/lue-hello-c

run_and_check args-env $'argc=3\nargv[0]=/tmp/lue-args-env\nargv[1]=alpha\nargv[2]=beta\nLUE_TEST_VALUE=works' \
    env LUE_TEST_VALUE=works "$emulator" /tmp/lue-args-env alpha beta

printf 'cat input\n' >/tmp/lue-cat-input
run_and_check cat-static "cat input" "$emulator" /tmp/lue-cat-static /tmp/lue-cat-input

run_and_check mmap-brk $'heap ok\nmmap ok' "$emulator" /tmp/lue-mmap-brk
run_and_check syscall-coverage "syscall coverage ok" "$emulator" /tmp/lue-syscall-coverage
run_and_check region-types $'LEft\nRIght' "$emulator" /tmp/lue-region-types
run_and_check_failure_output_contains region-dump "mmap [mmap]" "$emulator" /tmp/lue-region-dump
run_and_check_failure_output_contains shadow-memory "uninitialized guest memory read" "$emulator" /tmp/lue-shadow-memory
run_and_check signal-basic $'before\nhandled\nafter' "$emulator" /tmp/lue-signal-basic
run_and_check_host_signal host-signal
run_and_check fs-tls "fs ok" "$emulator" /tmp/lue-fs-tls
