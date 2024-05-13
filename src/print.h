#pragma once

#include <iostream>
#include <chrono>
#include <mutex>

#if defined __has_include && __has_include(<print>)
// Support for std::print is not yet available in GCC stdlib (as of now), but it is in clang
    #include <print>
    #define print_internal std::print
    #define print_internal_fmt_type std::format_string<Args...>
#elif defined __has_include && __has_include(<format>)
// Support for format is in clang 14 or above or in gcc13 or above
    #include <format>
    #define print_internal std::cout << std::format
    #define print_internal_fmt_type std::format_string<Args...>
#else
// If using an incomplete implementation of the standard, use fmt
    #include <fmt/format.h>
    #include <fmt/chrono.h>
    #define print_internal fmt::print
    #define print_internal_fmt_type fmt::format_string<Args...>
#endif

namespace print {
    namespace{
        bool verbose = false;
        std::mutex mtx;
        bool printed_status = false;
    }

    /**
     * @brief Set the verbose flag.
     *
     * This function sets the verbose flag to the specified value.
     *
     * @param v The value to set the verbose flag to.
     */
    [[maybe_unused]]
    static void set_verbose(bool v) {
        verbose = v;
    }

    /**
     * @brief Print a formatted message.
     *
     * This function prints a formatted message to the standard output.
     *
     * @tparam Args Variadic template for message arguments.
     * @param fmt The format string.
     * @param args The arguments to be formatted and printed.
     */
    template<typename ...Args>
    [[maybe_unused]]
    static void print(print_internal_fmt_type fmt, Args&& ...args) {
        std::lock_guard<std::mutex> lock(mtx);
        if (printed_status) {
            std::cout << "\x1b[A\x1b[K";
        }
        printed_status = false;
        print_internal(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Print a status message.
     *
     * This function prints a status message using the specified format and arguments.
     *
     * @tparam Args Variadic template for message arguments.
     * @param fmt The format string.
     * @param args The arguments to be formatted and printed.
     */
    template<typename ...Args>
    [[maybe_unused]]
    static void stat_print(print_internal_fmt_type fmt, Args&& ...args) {
        std::lock_guard<std::mutex> lock(mtx);
        if (printed_status) {
            std::cout << "\x1b[A\x1b[K";
        }
        printed_status = true;
        print_internal(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Print a verbose message.
     *
     * This function prints a verbose message using the specified format and arguments
     * if the 'verbose' flag is set to true.
     *
     * @tparam Args Variadic template for message arguments.
     * @param fmt The format string.
     * @param args The arguments to be formatted and printed.
     */
    template<typename ...Args>
    [[maybe_unused]]
    static void verbose_print(print_internal_fmt_type fmt, Args&& ...args) {
        if (!verbose) {
            return;
        }
        std::lock_guard<std::mutex> lock(mtx);
        if (printed_status) {
            std::cout << "\x1b[A\x1b[K";
        }
        printed_status = false;
        print_internal(fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Print a raw message.
     *
     * This function prints a raw message using the specified format and arguments
     * without any additional formatting or checks.
     *
     * @tparam Args Variadic template for message arguments.
     * @param fmt The format string.
     * @param args The arguments to be formatted and printed.
     */
    template<typename ...Args>
    [[maybe_unused]]
    static void raw_print(print_internal_fmt_type fmt, Args&& ...args) {
        std::lock_guard<std::mutex> lock(mtx);
        print_internal(fmt, std::forward<Args>(args)...);
    }
}

#undef print_internal
#undef print_internal_fmt_type

