#pragma once

namespace androidshield::anti_hook {

constexpr int FLAG_FRIDA_MAPS = 1 << 0;
constexpr int FLAG_XPOSED_MAPS = 1 << 1;
constexpr int FLAG_FRIDA_THREAD = 1 << 2;
constexpr int FLAG_FRIDA_FILE = 1 << 3;
constexpr int FLAG_INLINE_HOOK_HINT = 1 << 4;

/** Returns 0 if clean, otherwise bitmask of FLAG_*. */
int self_check();

int scan_maps();
int scan_threads();
int scan_files();

}  // namespace androidshield::anti_hook
