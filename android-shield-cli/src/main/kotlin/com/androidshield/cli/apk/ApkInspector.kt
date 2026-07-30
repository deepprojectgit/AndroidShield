package com.androidshield.cli.apk

import com.androidshield.core.integrity.DigestUtils
import com.androidshield.core.integrity.IntegrityMetadata
import com.androidshield.core.integrity.IntegrityMetadataCodec
import java.io.File
import java.util.zip.ZipFile

/**
 * Static analysis model of an APK/AAR/ZIP package.
 */
data class PackageAnalysis(
    val path: String,
    val kind: PackageKind,
    val fileSha256: String,
    val sizeBytes: Long,
    val entryCount: Int,
    val dexFiles: List<String>,
    val nativeLibraries: List<String>,
    val hasAndroidManifest: Boolean,
    val hasResourcesArsc: Boolean,
    val v1SigningEntries: List<String>,
    val hasIntegrityMetadata: Boolean,
    val integrityMetadata: IntegrityMetadata?,
    val encryptedAssetPaths: List<String>,
    val shieldMarkerHits: List<String>,
    val hasKotlinMetadata: Boolean,
)

enum class PackageKind {
    APK,
    AAR,
    AAB,
    ZIP,
    UNKNOWN,
}

/**
 * Offline inspector that treats APK/AAR/AAB as ZIP archives.
 */
object ApkInspector {
    private val AS1_MAGIC = byteArrayOf('A'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())

    fun inspect(file: File): PackageAnalysis {
        require(file.exists() && file.isFile) { "File not found: ${file.absolutePath}" }
        val kind = detectKind(file)
        val sha = file.inputStream().use { DigestUtils.sha256Hex(it) }

        val dex = mutableListOf<String>()
        val natives = mutableListOf<String>()
        val v1Sign = mutableListOf<String>()
        val encryptedAssets = mutableListOf<String>()
        val markers = mutableListOf<String>()
        var hasManifest = false
        var hasResources = false
        var hasIntegrity = false
        var integrity: IntegrityMetadata? = null
        var hasKotlin = false
        var entries = 0

        ZipFile(file).use { zip ->
            val zipEntries = zip.entries().toList()
            entries = zipEntries.size
            for (entry in zipEntries) {
                if (entry.isDirectory) continue
                val name = entry.name
                when {
                    name.matches(Regex("""classes\d*\.dex""")) || name.endsWith(".dex") && name.count { it == '/' } == 0 ->
                        dex += name
                    name.startsWith("lib/") && name.endsWith(".so") ->
                        natives += name
                    name.equals("AndroidManifest.xml", ignoreCase = true) ||
                        name == "manifest/AndroidManifest.xml" ->
                        hasManifest = true
                    name == "resources.arsc" ->
                        hasResources = true
                    name.startsWith("META-INF/") &&
                        (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC") || name.endsWith(".SF")) ->
                        v1Sign += name
                    name.contains("kotlin/kotlin.kotlin_builtins") || name.startsWith("kotlin/") ->
                        hasKotlin = true
                }

                if (name == "assets/androidshield/integrity.json" ||
                    name == "androidshield/integrity.json"
                ) {
                    hasIntegrity = true
                    integrity = runCatching {
                        zip.getInputStream(entry).use { IntegrityMetadataCodec.decode(it.readBytes()) }
                    }.getOrNull()
                }

                if (name.startsWith("assets/") && entry.size in 4..8_000_000) {
                    val header = zip.getInputStream(entry).use { input ->
                        val buf = ByteArray(3)
                        val read = input.read(buf)
                        if (read == 3) buf else null
                    }
                    if (header != null && header.contentEquals(AS1_MAGIC)) {
                        encryptedAssets += name
                    }
                }

                // Lightweight ASCII scan for shield markers in small uncompressed-looking entries
                if ((name.endsWith(".dex") || name.endsWith(".json") || name.endsWith(".so")) &&
                    entry.size < 64 * 1024 * 1024
                ) {
                    // Only probe JSON / names for markers to keep inspect fast; DEX scanned separately below.
                    if (name.endsWith(".json") && name.contains("androidshield")) {
                        markers += "json:$name"
                    }
                }
            }

            // Scan first DEX for ASCII markers (AndroidShield package names)
            dex.take(1).forEach { dexName ->
                val entry = zip.getEntry(dexName) ?: return@forEach
                zip.getInputStream(entry).use { input ->
                    val bytes = input.readBytes()
                    scanAsciiMarkers(bytes).forEach { markers += it }
                }
            }

            // Native shield library
            if (natives.any { it.contains("libandroidshield") }) {
                markers += "native:libandroidshield"
            }
        }

        return PackageAnalysis(
            path = file.absolutePath,
            kind = kind,
            fileSha256 = sha,
            sizeBytes = file.length(),
            entryCount = entries,
            dexFiles = dex.sorted(),
            nativeLibraries = natives.sorted(),
            hasAndroidManifest = hasManifest,
            hasResourcesArsc = hasResources,
            v1SigningEntries = v1Sign.sorted(),
            hasIntegrityMetadata = hasIntegrity,
            integrityMetadata = integrity,
            encryptedAssetPaths = encryptedAssets.sorted(),
            shieldMarkerHits = markers.distinct().sorted(),
            hasKotlinMetadata = hasKotlin,
        )
    }

    private fun detectKind(file: File): PackageKind {
        val name = file.name.lowercase()
        return when {
            name.endsWith(".apk") -> PackageKind.APK
            name.endsWith(".aar") -> PackageKind.AAR
            name.endsWith(".aab") -> PackageKind.AAB
            name.endsWith(".zip") -> PackageKind.ZIP
            else -> PackageKind.UNKNOWN
        }
    }

    private fun scanAsciiMarkers(bytes: ByteArray): List<String> {
        val hay = bytes.toString(Charsets.ISO_8859_1)
        val hits = mutableListOf<String>()
        val needles = listOf(
            "com/androidshield/runtime" to "dex:runtime",
            "com/androidshield/nativebridge" to "dex:nativebridge",
            "ShieldStringDecryptor" to "dex:string_decryptor",
            "BuildShieldSecrets" to "dex:build_secrets",
            "AndroidShield" to "dex:android_shield",
            "libandroidshield" to "dex:libandroidshield_ref",
        )
        needles.forEach { (needle, label) ->
            if (hay.contains(needle)) hits += label
        }
        return hits
    }
}
