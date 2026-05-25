#pragma once

#include "Types.h"

#include <type_traits>

namespace LUE {

template<typename T>
class ValueWithShadow {
public:
    static_assert(std::is_integral_v<T>);

    ValueWithShadow() = default;
    ValueWithShadow(T value, T shadow)
        : m_value(value)
        , m_shadow(shadow)
    {
    }

    static ValueWithShadow initialized(T value) { return { value, 0 }; }
    static ValueWithShadow uninitialized(T value) { return { value, static_cast<T>(~T {}) }; }

    T value() const { return m_value; }
    T shadow() const { return m_shadow; }
    bool is_initialized() const { return m_shadow == 0; }
    bool is_uninitialized() const { return m_shadow != 0; }

private:
    T m_value {};
    T m_shadow {};
};

}
