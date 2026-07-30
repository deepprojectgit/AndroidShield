package com.androidshield.core.integrity

import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat

/**
 * Result of comparing expected [IntegrityMetadata] digests against observed values.
 */
data class IntegrityCheckResult(
    val matches: Boolean,
    val mismatchedFields: List<String> = emptyList(),
    val threats: List<Threat> = emptyList(),
) {
    companion object {
        fun ok(): IntegrityCheckResult = IntegrityCheckResult(matches = true)
    }
}

/**
 * Observed digests collected at runtime for comparison.
 */
data class ObservedIntegrity(
    val dexDigestSha256: String = "",
    val manifestDigestSha256: String = "",
    val resourcesDigestSha256: String = "",
    val nativeLibsDigestSha256: String = "",
    val buildFingerprint: String = "",
)

/**
 * Verifies [IntegrityMetadata] against [ObservedIntegrity] using constant-time hex compares
 * when both sides provide a non-empty digest.
 */
object IntegrityVerifier {
    fun verify(expected: IntegrityMetadata, observed: ObservedIntegrity): IntegrityCheckResult {
        val mismatches = mutableListOf<String>()

        fun check(field: String, expectedValue: String, observedValue: String) {
            if (expectedValue.isBlank() || observedValue.isBlank()) return
            if (!DigestUtils.constantTimeEquals(expectedValue.lowercase(), observedValue.lowercase())) {
                mismatches += field
            }
        }

        check("buildFingerprint", expected.buildFingerprint, observed.buildFingerprint)
        check("dexDigestSha256", expected.dexDigestSha256, observed.dexDigestSha256)
        check("manifestDigestSha256", expected.manifestDigestSha256, observed.manifestDigestSha256)
        check("resourcesDigestSha256", expected.resourcesDigestSha256, observed.resourcesDigestSha256)
        check("nativeLibsDigestSha256", expected.nativeLibsDigestSha256, observed.nativeLibsDigestSha256)

        if (mismatches.isEmpty()) {
            return IntegrityCheckResult.ok()
        }

        val threats = mismatches.map { field ->
            Threat(
                id = "integrity.mismatch.$field",
                title = "Integrity mismatch: $field",
                severity = Severity.CRITICAL,
                description = "Observed digest for `$field` does not match build-time metadata",
                recommendation = "Refuse to run or degrade features — APK may be repackaged/tampered",
            )
        }
        return IntegrityCheckResult(matches = false, mismatchedFields = mismatches, threats = threats)
    }
}
