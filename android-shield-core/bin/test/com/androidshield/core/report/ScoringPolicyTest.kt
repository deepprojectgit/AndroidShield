package com.androidshield.core.report

import com.androidshield.core.model.Severity
import com.androidshield.testing.ThreatFixtures
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ScoringPolicyTest {
    @Test
    fun defaultPolicy_criticalMarksInsecure() {
        val report = SecurityReportBuilder.fromThreats(listOf(ThreatFixtures.sampleCritical()))
        assertThat(report.secure).isFalse()
        assertThat(report.score).isLessThan(100)
    }

    @Test
    fun strictPolicy_mediumIsInsecure() {
        val medium = ThreatFixtures.sampleLow().copy(
            id = "test.medium",
            severity = Severity.MEDIUM,
            title = "Medium"
        )
        val report = SecurityReportBuilder.fromThreats(listOf(medium), ScoringPolicy.STRICT)
        assertThat(report.secure).isFalse()
    }

    @Test
    fun jsonRoundTrip() {
        val report = SecurityReportBuilder.fromThreats(emptyList())
        val restored = SecurityReportBuilder.fromJson(SecurityReportBuilder.toJson(report))
        assertThat(restored).isEqualTo(report)
    }
}
