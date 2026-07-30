package com.androidshield.core.crypto

/**
 * Supported AEAD algorithms for string / resource / constant protection.
 *
 * Mirrors [com.androidshield.annotations.EncryptAlgorithm] for core/runtime without
 * pulling annotations into pure JVM consumers.
 */
enum class ShieldAlgorithm {
    AES_GCM,
    CHACHA20_POLY1305,
}
