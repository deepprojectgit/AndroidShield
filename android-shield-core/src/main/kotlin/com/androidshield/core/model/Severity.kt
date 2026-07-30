package com.androidshield.core.model

import kotlinx.serialization.Serializable

/**
 * Severity classification for a detected security threat.
 */
@Serializable
enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
