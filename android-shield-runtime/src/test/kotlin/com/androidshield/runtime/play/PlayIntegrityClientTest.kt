package com.androidshield.runtime.play

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class PlayIntegrityClientTest {
    @Test
    fun threatsFromVerdict_flagsMissingLevels() {
        val threats = PlayIntegrityClient.threatsFromVerdict(emptyList())
        assertThat(threats.map { it.id }).containsAtLeast(
            "play.integrity.basic_failed",
            "play.integrity.device_failed",
            "play.integrity.strong_failed",
        )
    }

    @Test
    fun threatsFromVerdict_allLevelsOk() {
        val threats = PlayIntegrityClient.threatsFromVerdict(
            listOf("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"),
        )
        assertThat(threats).isEmpty()
    }
}
