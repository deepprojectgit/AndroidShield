#pragma once

#include <cstdint>

namespace androidshield::anti_debug {

/** Bit flags returned by checks (combine with |). */
constexpr int FLAG_TRACER_PID = 1 << 0;
constexpr int FLAG_PTRACE = 1 << 1;
constexpr int FLAG_DEBUGGER_PORT = 1 << 2;
constexpr int FLAG_TIMING = 1 << 3;

/**
 * Runs all anti-debug checks. Returns 0 if clean, otherwise a bitmask of FLAG_*.
 */
int self_check();

int check_tracer_pid();
int check_ptrace();
int check_debugger_ports();
int check_timing();

}  // namespace androidshield::anti_debug
