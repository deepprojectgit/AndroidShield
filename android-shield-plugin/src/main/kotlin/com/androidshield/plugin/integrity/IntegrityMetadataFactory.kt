package com.androidshield.plugin.integrity

import com.androidshield.core.integrity.DigestUtils
import com.androidshield.core.integrity.IntegrityMetadata
import java.io.File
import java.security.MessageDigest

/**
 * Builds SHA-256 digests and integrity metadata for a variant.
 */
object IntegrityMetadataFactory {
    fun fingerprint(
        packageName: String,
        variantName: String,
        materials: List<File>,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(packageName.toByteArray(Charsets.UTF_8))
        digest.update(variantName.toByteArray(Charsets.UTF_8))
        materials.filter { it.exists() }.sortedBy { it.absolutePath }.forEach { file ->
            digest.update(file.name.toByteArray(Charsets.UTF_8))
            digest.update(file.readBytes())
        }
        return DigestUtils.toHex(digest.digest())
    }

    fun sha256(file: File): String {
        if (!file.exists()) return ""
        return file.inputStream().use { DigestUtils.sha256Hex(it) }
    }

    fun sha256Bytes(bytes: ByteArray): String = DigestUtils.sha256Hex(bytes)

    fun create(
        packageName: String,
        variantName: String,
        fingerprint: String,
        dexDigest: String = "",
        manifestDigest: String = "",
        resourcesDigest: String = "",
        nativeDigest: String = "",
        stringEncryption: Boolean,
        resourceEncryption: Boolean,
    ): IntegrityMetadata =
        IntegrityMetadata(
            buildFingerprint = fingerprint,
            generatedAtEpochMs = System.currentTimeMillis(),
            packageName = packageName,
            variantName = variantName,
            dexDigestSha256 = dexDigest,
            manifestDigestSha256 = manifestDigest,
            resourcesDigestSha256 = resourcesDigest,
            nativeLibsDigestSha256 = nativeDigest,
            stringEncryptionEnabled = stringEncryption,
            resourceEncryptionEnabled = resourceEncryption,
        )
}
