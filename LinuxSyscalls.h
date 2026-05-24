#pragma once

#include "Types.h"

namespace LUE {

class Emulator;

class LinuxSyscalls {
public:
    static u64 dispatch(Emulator&, u64 number);
};

}
