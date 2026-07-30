package com.androidshield.annotations

/**
 * Marks string / resource content that must be encrypted at build time.
 */
@MustBeDocumented
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.FIELD,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.FUNCTION
)
annotation class ShieldEncrypt(
    val algorithm: EncryptAlgorithm = EncryptAlgorithm.AES_GCM
)

/**
 * Supported build-time encryption algorithms.
 */
enum class EncryptAlgorithm {
    AES_GCM,
    CHACHA20
}
