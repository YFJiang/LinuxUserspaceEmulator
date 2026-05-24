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

run_and_check hello-static "hello from guest" "$emulator" /tmp/lue-hello-static
run_and_check hello-dyn "hello from C guest" "$emulator" /tmp/lue-hello-dyn
run_and_check_failure_contains symbol-backtrace "$emulator" /tmp/lue-symbol-backtrace
run_and_check hello-c "hello from C guest" "$emulator" /tmp/lue-hello-c

run_and_check args-env $'argc=3\nargv[0]=/tmp/lue-args-env\nargv[1]=alpha\nargv[2]=beta\nLUE_TEST_VALUE=works' \
    env LUE_TEST_VALUE=works "$emulator" /tmp/lue-args-env alpha beta

printf 'cat input\n' >/tmp/lue-cat-input
run_and_check cat-static "cat input" "$emulator" /tmp/lue-cat-static /tmp/lue-cat-input

run_and_check mmap-brk $'heap ok\nmmap ok' "$emulator" /tmp/lue-mmap-brk
run_and_check fs-tls "fs ok" "$emulator" /tmp/lue-fs-tls
