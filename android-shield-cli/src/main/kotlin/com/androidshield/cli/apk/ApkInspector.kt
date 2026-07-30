package com.androidshield.cli.apk

import com.androidshield.core.integrity.DigestUtils
import com.androidshield.core.integrity.IntegrityMetadata
import com.androidshield.core.integrity.IntegrityMetadataCodec
import java.io.File
import java.util.zip.ZipEntry
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
    val hasKotlinMetadata: Boolean
)

enum class PackageKind {
    APK,
    AAR,
    AAB,
    ZIP,
    UNKNOWN
}

/**
 * Offline inspector that treats APK/AAR/AAB as ZIP archives.
 */
object ApkInspector {
    fun inspect(file: File): PackageAnalysis {
        require(file.exists() && file.isFile) { "File not found: ${file.absolutePath}" }
        val kind = PackageKindDetector.detect(file)
        val sha = file.inputStream().use { DigestUtils.sha256Hex(it) }
        val scan = ZipFile(file).use { ZipPackageScanner.scan(it) }

        return PackageAnalysis(
            path = file.absolutePath,
            kind = kind,
            fileSha256 = sha,
            sizeBytes = file.length(),
            entryCount = scan.entryCount,
            dexFiles = scan.dexFiles.sorted(),
            nativeLibraries = scan.nativeLibraries.sorted(),
            hasAndroidManifest = scan.hasAndroidManifest,
            hasResourcesArsc = scan.hasResourcesArsc,
            v1SigningEntries = scan.v1SigningEntries.sorted(),
            hasIntegrityMetadata = scan.hasIntegrityMetadata,
            integrityMetadata = scan.integrityMetadata,
            encryptedAssetPaths = scan.encryptedAssetPaths.sorted(),
            shieldMarkerHits = scan.shieldMarkerHits.distinct().sorted(),
            hasKotlinMetadata = scan.hasKotlinMetadata
        )
    }
}

internal object PackageKindDetector {
    fun detect(file: File): PackageKind {
        val name = file.name.lowercase()
        return when {
            name.endsWith(".apk") -> PackageKind.APK
            name.endsWith(".aar") -> PackageKind.AAR
            name.endsWith(".aab") -> PackageKind.AAB
            name.endsWith(".zip") -> PackageKind.ZIP
            else -> PackageKind.UNKNOWN
        }
    }
}

internal object ZipPackageScanner {
    private val as1Magic = byteArrayOf('A'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())

    fun scan(zip: ZipFile): ZipScanResult {
        val state = ZipScanState()
        val zipEntries = zip.entries().toList()
        state.entryCount = zipEntries.size
        for (entry in zipEntries) {
            if (!entry.isDirectory) {
                ZipEntryClassifier.classify(zip, entry, state, as1Magic)
            }
        }
        DexMarkerScanner.scanFirstDex(zip, state)
        if (state.natives.any { it.contains("libandroidshield") }) {
            state.markers += "native:libandroidshield"
        }
        return state.toResult()
    }
}

internal object ZipEntryClassifier {
    fun classify(zip: ZipFile, entry: ZipEntry, state: ZipScanState, as1Magic: ByteArray) {
        val name = entry.name
        recordStructuralFlags(name, state)
        recordIntegrity(zip, entry, name, state)
        recordAs1Asset(zip, entry, name, state, as1Magic)
        val isShieldJson = name.endsWith(".json") && name.contains("androidshield")
        if (isShieldJson && entry.size < 64 * 1024 * 1024) {
            state.markers += "json:$name"
        }
    }

    private fun recordStructuralFlags(name: String, state: ZipScanState) {
        when {
            ZipEntryNames.isDex(name) -> state.dex += name
            name.startsWith("lib/") && name.endsWith(".so") -> state.natives += name
            ZipEntryNames.isManifest(name) -> state.hasManifest = true
            name == "resources.arsc" -> state.hasResources = true
            ZipEntryNames.isV1Signing(name) -> state.v1Sign += name
            name.contains("kotlin/kotlin.kotlin_builtins") || name.startsWith("kotlin/") ->
                state.hasKotlin = true
        }
    }

    private fun recordIntegrity(zip: ZipFile, entry: ZipEntry, name: String, state: ZipScanState) {
        if (!ZipEntryNames.isIntegrity(name)) return
        state.hasIntegrity = true
        state.integrity = runCatching {
            zip.getInputStream(entry).use { IntegrityMetadataCodec.decode(it.readBytes()) }
        }.getOrNull()
    }

    private fun recordAs1Asset(
        zip: ZipFile,
        entry: ZipEntry,
        name: String,
        state: ZipScanState,
        as1Magic: ByteArray
    ) {
        if (!name.startsWith("assets/") || entry.size !in 4..8_000_000) return
        val header = zip.getInputStream(entry).use { input ->
            val buf = ByteArray(3)
            val read = input.read(buf)
            if (read == 3) buf else null
        }
        if (header != null && header.contentEquals(as1Magic)) {
            state.encryptedAssets += name
        }
    }
}

internal object ZipEntryNames {
    fun isDex(name: String): Boolean = name.matches(Regex("""classes\d*\.dex""")) ||
        (name.endsWith(".dex") && name.count { it == '/' } == 0)

    fun isManifest(name: String): Boolean = name.equals("AndroidManifest.xml", ignoreCase = true) ||
        name == "manifest/AndroidManifest.xml"

    fun isV1Signing(name: String): Boolean {
        if (!name.startsWith("META-INF/")) return false
        return name.endsWith(".RSA") ||
            name.endsWith(".DSA") ||
            name.endsWith(".EC") ||
            name.endsWith(".SF")
    }

    fun isIntegrity(name: String): Boolean = name == "assets/androidshield/integrity.json" ||
        name == "androidshield/integrity.json"
}

internal object DexMarkerScanner {
    fun scanFirstDex(zip: ZipFile, state: ZipScanState) {
        state.dex.take(1).forEach { dexName ->
            val entry = zip.getEntry(dexName) ?: return@forEach
            zip.getInputStream(entry).use { input ->
                scanAsciiMarkers(input.readBytes()).forEach { state.markers += it }
            }
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
            "libandroidshield" to "dex:libandroidshield_ref"
        )
        needles.forEach { (needle, label) ->
            if (hay.contains(needle)) hits += label
        }
        return hits
    }
}

internal class ZipScanState {
    var entryCount = 0
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

    fun toResult() = ZipScanResult(
        entryCount = entryCount,
        dexFiles = dex.toList(),
        nativeLibraries = natives.toList(),
        v1SigningEntries = v1Sign.toList(),
        encryptedAssetPaths = encryptedAssets.toList(),
        shieldMarkerHits = markers.toList(),
        hasAndroidManifest = hasManifest,
        hasResourcesArsc = hasResources,
        hasIntegrityMetadata = hasIntegrity,
        integrityMetadata = integrity,
        hasKotlinMetadata = hasKotlin
    )
}

internal data class ZipScanResult(
    val entryCount: Int,
    val dexFiles: List<String>,
    val nativeLibraries: List<String>,
    val v1SigningEntries: List<String>,
    val encryptedAssetPaths: List<String>,
    val shieldMarkerHits: List<String>,
    val hasAndroidManifest: Boolean,
    val hasResourcesArsc: Boolean,
    val hasIntegrityMetadata: Boolean,
    val integrityMetadata: IntegrityMetadata?,
    val hasKotlinMetadata: Boolean
)
