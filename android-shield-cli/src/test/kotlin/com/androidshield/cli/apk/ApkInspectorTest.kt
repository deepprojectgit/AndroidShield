package com.androidshield.cli.apk

import com.androidshield.cli.analyze.ProtectionAnalyzer
import com.google.common.truth.Truth.assertThat
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ApkInspectorTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun inspect_minimalApk_findsDexAndManifest() {
        val apk = tmp.newFile("app.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(byteArrayOf(0, 1, 2))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            // Include ASCII marker for runtime
            val payload = ByteArray(64) { 0 }
            val marker = "com/androidshield/runtime".toByteArray()
            System.arraycopy(marker, 0, payload, 0, marker.size)
            zip.write(payload)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libandroidshield.so"))
            zip.write(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/androidshield/integrity.json"))
            zip.write(
                """
                {
                  "version":1,
                  "buildFingerprint":"abc",
                  "generatedAtEpochMs":1,
                  "stringEncryptionEnabled":true,
                  "resourceEncryptionEnabled":true
                }
                """.trimIndent().toByteArray()
            )
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/shield/secret.bin"))
            zip.write(byteArrayOf('A'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte(), 12))
            zip.closeEntry()
        }

        val analysis = ApkInspector.inspect(apk)
        assertThat(analysis.kind).isEqualTo(PackageKind.APK)
        assertThat(analysis.hasAndroidManifest).isTrue()
        assertThat(analysis.dexFiles).contains("classes.dex")
        assertThat(analysis.hasIntegrityMetadata).isTrue()
        assertThat(analysis.encryptedAssetPaths).contains("assets/shield/secret.bin")
        assertThat(analysis.shieldMarkerHits).contains("native:libandroidshield")
        assertThat(analysis.shieldMarkerHits.any { it.contains("runtime") }).isTrue()
    }

    @Test
    fun analyze_minimalProtectedApk_isMostlySecure() {
        val apk = tmp.newFile("protected.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(byteArrayOf(1))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex"))
            val markerBlob =
                "XXXX" +
                    "com/androidshield/runtime" +
                    "ShieldStringDecryptor" +
                    "BuildShieldSecrets"
            zip.write(markerBlob.toByteArray())
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libandroidshield.so"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            zip.write(byteArrayOf(9))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/androidshield/integrity.json"))
            val integrityJson =
                """
                {
                  "version":1,
                  "buildFingerprint":"fp",
                  "generatedAtEpochMs":1,
                  "stringEncryptionEnabled":true,
                  "resourceEncryptionEnabled":true
                }
                """.trimIndent()
            zip.write(integrityJson.toByteArray())
            zip.closeEntry()
        }

        val report = ProtectionAnalyzer.analyze(ApkInspector.inspect(apk))
        assertThat(report.threats.none { it.id == "cli.shield.runtime_missing" }).isTrue()
        assertThat(report.threats.none { it.id == "cli.package.no_dex" }).isTrue()
    }
}
