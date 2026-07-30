#pragma once

namespace androidshield::memory {

constexpr int FLAG_RWX = 1 << 0;
constexpr int FLAG_SUSPICIOUS_NAME = 1 << 1;

/** Returns 0 if memory maps look normal. */
int self_check();

}  // namespace androidshield::memory
