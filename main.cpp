#include "Emulator.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

std::string find_executable(const std::string& command)
{
    if (command.find('/') != std::string::npos)
        return command;

    const char* path_env = std::getenv("PATH");
    if (!path_env)
        return {};

    std::stringstream paths(path_env);
    std::string directory;
    while (std::getline(paths, directory, ':')) {
        if (directory.empty())
            directory = ".";
        std::string candidate = directory + "/" + command;
        if (::access(candidate.c_str(), X_OK) == 0)
            return candidate;
    }
    return {};
}

void print_usage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " [options] <program> [args...]\n"
              << "\n"
              << "Options:\n"
              << "  -h, --help             Show this help text and exit\n"
              << "      --trace            Print every guest instruction and registers\n"
              << "      --trace-syscalls   Print guest Linux syscalls\n"
              << "      --backtrace-on-exit\n"
              << "                         Print a symbolic guest backtrace on normal exit\n";
}

}

int main(int argc, char** argv, char** envp)
{
    LUE::EmulatorOptions options;
    std::vector<std::string> guest_arguments;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (std::strcmp(argv[i], "--trace") == 0) {
            options.trace = true;
            continue;
        }
        if (std::strcmp(argv[i], "--trace-syscalls") == 0) {
            options.trace_syscalls = true;
            continue;
        }
        if (std::strcmp(argv[i], "--backtrace-on-exit") == 0) {
            options.backtrace_on_exit = true;
            continue;
        }
        guest_arguments.emplace_back(argv[i]);
        for (++i; i < argc; ++i)
            guest_arguments.emplace_back(argv[i]);
        break;
    }

    if (guest_arguments.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    auto executable_path = find_executable(guest_arguments[0]);
    if (executable_path.empty()) {
        std::cerr << "LinuxUserspaceEmulator: cannot find executable: " << guest_arguments[0] << "\n";
        return 1;
    }

    std::vector<std::string> environment;
    for (size_t i = 0; envp[i]; ++i)
        environment.emplace_back(envp[i]);

    LUE::Emulator emulator(executable_path, guest_arguments, environment, options);
    return emulator.exec();
}
