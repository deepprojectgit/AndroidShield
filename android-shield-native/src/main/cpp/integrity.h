#pragma once

#include <cstddef>
#include <cstdint>

namespace androidshield::integrity {

/** FNV-1a 64-bit checksum (fast integrity fingerprint, not cryptographic). */
uint64_t checksum(const uint8_t *data, size_t length);

/** SHA-256 digest into out[32]. Returns false on null args. */
bool sha256(const uint8_t *data, size_t length, uint8_t out[32]);

}  // namespace androidshield::integrity
