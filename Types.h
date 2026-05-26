#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace LUE {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

static constexpr u64 page_size = 4096;

class EmulatorError final : public std::runtime_error {
public:
    explicit EmulatorError(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

class GuestExit final : public std::exception {
public:
    explicit GuestExit(int status)
        : m_status(status)
    {
    }

    int status() const { return m_status; }

private:
    int m_status { 0 };
};

inline u64 page_align_down(u64 value)
{
    // Round down to the start of the containing page.
    return value & ~(page_size - 1);
}

inline u64 page_align_up(u64 value)
{
    // Round up to the next page boundary, leaving aligned values unchanged.
    return (value + page_size - 1) & ~(page_size - 1);
}

template<typename T>
inline T read_unaligned(const u8* data)
{
    T value {};
    std::memcpy(&value, data, sizeof(T));
    return value;
}

template<typename T>
inline void write_unaligned(u8* data, T value)
{
    std::memcpy(data, &value, sizeof(T));
}

inline std::string hex(u64 value, int width = 0)
{
    std::ostringstream builder;
    builder << "0x" << std::hex << std::setfill('0');
    if (width > 0)
        builder << std::setw(width);
    builder << value;
    return builder.str();
}

inline std::string errno_string(int err)
{
    return "-" + std::to_string(err);
}

}
