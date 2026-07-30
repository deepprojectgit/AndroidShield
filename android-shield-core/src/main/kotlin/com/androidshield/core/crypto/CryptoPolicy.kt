package com.androidshield.core.crypto

/**
 * Policy describing which string literals should be encrypted at build time.
 *
 * Used by the Gradle plugin heuristics and shared with tooling/tests.
 */
data class StringEncryptionPolicy(
    val minLength: Int = 4,
    val encryptUrls: Boolean = true,
    val encryptSql: Boolean = true,
    val encryptSecrets: Boolean = true,
    val encryptLongLiterals: Boolean = true,
    val longLiteralThreshold: Int = 12,
    val algorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM
) {
    /**
     * Returns `true` when [value] matches encryption heuristics.
     */
    fun shouldEncrypt(value: String): Boolean {
        if (value.length < minLength) return false
        val lower = value.lowercase()
        val looksLikeUrl = encryptUrls &&
            (value.startsWith("http://") || value.startsWith("https://"))
        val looksLikeSecret = encryptSecrets && SECRET_HINTS.any { lower.contains(it) }
        val looksLikeSql = encryptSql && SQL_HINTS.any { lower.contains(it) }
        val looksLong = encryptLongLiterals && value.length >= longLiteralThreshold
        val looksLikePath = value.contains('/') && value.contains('.')
        return looksLikeUrl || looksLikeSecret || looksLikeSql || looksLong || looksLikePath
    }

    companion object {
        val DEFAULT: StringEncryptionPolicy = StringEncryptionPolicy()

        private val SECRET_HINTS = listOf(
            "api",
            "token",
            "secret",
            "password",
            "jwt",
            "bearer",
            "key=",
            "auth"
        )
        private val SQL_HINTS = listOf(
            "select ",
            "insert ",
            "update ",
            "delete ",
            "from "
        )
    }
}

/**
 * Build/runtime crypto policy knobs shared across modules.
 */
data class CryptoPolicy(
    val stringAlgorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
    val resourceAlgorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
    val constantAlgorithm: ShieldAlgorithm = ShieldAlgorithm.AES_GCM,
    val stringEncryption: StringEncryptionPolicy = StringEncryptionPolicy.DEFAULT
) {
    companion object {
        val DEFAULT: CryptoPolicy = CryptoPolicy()
    }
}
