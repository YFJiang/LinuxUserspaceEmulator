cmake_minimum_required(VERSION 3.20)
project(LinuxUserspaceEmulator LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "LinuxUserspaceEmulator currently requires a Linux host")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(LinuxUserspaceEmulator
    ELFLoader.cpp
    Emulator.cpp
    ELFSymbols.cpp
    LinuxSyscalls.cpp
    SoftCPU64.cpp
    SoftMMU.cpp
    main.cpp
)

target_compile_options(LinuxUserspaceEmulator PRIVATE -Wall -Wextra)
target_compile_definitions(LinuxUserspaceEmulator PRIVATE LUE_HOST_LINUX=1 _GNU_SOURCE)
