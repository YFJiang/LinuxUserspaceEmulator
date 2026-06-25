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

// Taint propagation: an instruction's result is only considered initialized when
// every source operand it derived from was initialized. The shadow convention is
// "0 == initialized, any set bit == uninitialized", so combining sources is just
// an OR of their uninitialized-ness. These mirror the helpers the SerenityOS
// UserspaceEmulator threads through every ALU operation.
template<typename T>
inline ValueWithShadow<T> shadow_wrap_with_taint_from(T value, bool tainted)
{
    return tainted ? ValueWithShadow<T>::uninitialized(value) : ValueWithShadow<T>::initialized(value);
}

template<typename T, typename A>
inline ValueWithShadow<T> shadow_wrap_with_taint_from(T value, const ValueWithShadow<A>& a)
{
    return shadow_wrap_with_taint_from(value, a.is_uninitialized());
}

template<typename T, typename A, typename B>
inline ValueWithShadow<T> shadow_wrap_with_taint_from(T value, const ValueWithShadow<A>& a, const ValueWithShadow<B>& b)
{
    return shadow_wrap_with_taint_from(value, a.is_uninitialized() || b.is_uninitialized());
}

template<typename T, typename A, typename B, typename C>
inline ValueWithShadow<T> shadow_wrap_with_taint_from(T value, const ValueWithShadow<A>& a, const ValueWithShadow<B>& b, const ValueWithShadow<C>& c)
{
    return shadow_wrap_with_taint_from(value, a.is_uninitialized() || b.is_uninitialized() || c.is_uninitialized());
}

}
