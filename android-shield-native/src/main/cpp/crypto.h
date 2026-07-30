#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace androidshield::crypto {

/**
 * Mirrors Java KeyScrambler — XOR with SHA-256 derived mask from seed.
 */
bool unscramble_key(
        const uint8_t *scrambled,
        size_t scrambled_len,
        const uint8_t *seed,
        size_t seed_len,
        std::vector<uint8_t> *out);

/**
 * Decrypts AES-256-GCM by calling Kotlin AesGcmCipher via JNI (stable / no OpenSSL dep).
 * Declared here; implemented in decrypt_jni.cpp with JNIEnv.
 */
}  // namespace androidshield::crypto
