package com.androidshield.core.integrity

import kotlinx.serialization.Serializable

/**
 * Build-time integrity metadata embedded for runtime anti-tamper checks.
 */
@Serializable
data class IntegrityMetadata(
    val version: Int = 1,
    val buildFingerprint: String,
    val generatedAtEpochMs: Long,
    val packageName: String = "",
    val variantName: String = "",
    val dexDigestSha256: String = "",
    val manifestDigestSha256: String = "",
    val resourcesDigestSha256: String = "",
    val nativeLibsDigestSha256: String = "",
    val stringEncryptionEnabled: Boolean = false,
    val resourceEncryptionEnabled: Boolean = false
)
