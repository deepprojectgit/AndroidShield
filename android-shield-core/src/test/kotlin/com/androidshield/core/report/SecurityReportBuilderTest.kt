package com.androidshield.core.report

import com.androidshield.testing.ThreatFixtures
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class SecurityReportBuilderTest {
    @Test
    fun emptyThreats_areSecureWithFullScore() {
        val report = SecurityReportBuilder.fromThreats(emptyList())
        assertThat(report.secure).isTrue()
        assertThat(report.score).isEqualTo(100)
        assertThat(report.threats).isEmpty()
    }

    @Test
    fun criticalThreat_marksInsecureAndReducesScore() {
        val report = SecurityReportBuilder.fromThreats(listOf(ThreatFixtures.sampleCritical()))
        assertThat(report.secure).isFalse()
        assertThat(report.score).isLessThan(100)
        assertThat(report.threats).hasSize(1)
    }

    @Test
    fun toJson_containsExpectedKeys() {
        val json = SecurityReportBuilder.toJson(SecurityReportBuilder.fromThreats(emptyList()))
        assertThat(json).contains("\"secure\"")
        assertThat(json).contains("\"score\"")
        assertThat(json).contains("\"threats\"")
    }
}
