package com.androidshield.core.config

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Shared protection feature flags used by the Gradle DSL and runtime.
 *
 * Runtime may apply a subset; build-time encryption flags are primarily consumed by the plugin.
 */
@Serializable
data class ShieldConfig(
    val antiDebug: Boolean = true,
    val antiTamper: Boolean = true,
    val antiHook: Boolean = true,
    val rootDetection: Boolean = true,
    val emulatorDetection: Boolean = true,
    val runtimeProtection: Boolean = true,
    val playIntegrity: Boolean = false,
    val stringEncryption: Boolean = true,
    val resourceEncryption: Boolean = true,
    val sslPinning: Boolean = true,
    val nativeProtection: Boolean = true,
    val constantEncryption: Boolean = true,
    val bytecodeObfuscation: Boolean = true,
    val stripMetadata: Boolean = true,
    val obfuscationIntensity: Int = 1,
    val protectPackages: List<String> = emptyList(),
) {
    init {
        require(obfuscationIntensity in 1..3) {
            "obfuscationIntensity must be 1..3, was $obfuscationIntensity"
        }
    }

    /** Feature map for build/runtime reports. */
    fun featureFlags(): Map<String, Boolean> = mapOf(
        "antiDebug" to antiDebug,
        "antiTamper" to antiTamper,
        "antiHook" to antiHook,
        "rootDetection" to rootDetection,
        "emulatorDetection" to emulatorDetection,
        "runtimeProtection" to runtimeProtection,
        "playIntegrity" to playIntegrity,
        "stringEncryption" to stringEncryption,
        "resourceEncryption" to resourceEncryption,
        "sslPinning" to sslPinning,
        "nativeProtection" to nativeProtection,
        "constantEncryption" to constantEncryption,
        "bytecodeObfuscation" to bytecodeObfuscation,
        "stripMetadata" to stripMetadata,
    )

    class Builder {
        private var antiDebug: Boolean = true
        private var antiTamper: Boolean = true
        private var antiHook: Boolean = true
        private var rootDetection: Boolean = true
        private var emulatorDetection: Boolean = true
        private var runtimeProtection: Boolean = true
        private var playIntegrity: Boolean = false
        private var stringEncryption: Boolean = true
        private var resourceEncryption: Boolean = true
        private var sslPinning: Boolean = true
        private var nativeProtection: Boolean = true
        private var constantEncryption: Boolean = true
        private var bytecodeObfuscation: Boolean = true
        private var stripMetadata: Boolean = true
        private var obfuscationIntensity: Int = 1
        private var protectPackages: List<String> = emptyList()

        fun antiDebug(value: Boolean) = apply { antiDebug = value }
        fun antiTamper(value: Boolean) = apply { antiTamper = value }
        fun antiHook(value: Boolean) = apply { antiHook = value }
        fun rootDetection(value: Boolean) = apply { rootDetection = value }
        fun emulatorDetection(value: Boolean) = apply { emulatorDetection = value }
        fun runtimeProtection(value: Boolean) = apply { runtimeProtection = value }
        fun playIntegrity(value: Boolean) = apply { playIntegrity = value }
        fun stringEncryption(value: Boolean) = apply { stringEncryption = value }
        fun resourceEncryption(value: Boolean) = apply { resourceEncryption = value }
        fun sslPinning(value: Boolean) = apply { sslPinning = value }
        fun nativeProtection(value: Boolean) = apply { nativeProtection = value }
        fun constantEncryption(value: Boolean) = apply { constantEncryption = value }
        fun bytecodeObfuscation(value: Boolean) = apply { bytecodeObfuscation = value }
        fun stripMetadata(value: Boolean) = apply { stripMetadata = value }
        fun obfuscationIntensity(value: Int) = apply { obfuscationIntensity = value }
        fun protectPackages(value: List<String>) = apply { protectPackages = value }

        fun build(): ShieldConfig = ShieldConfig(
            antiDebug = antiDebug,
            antiTamper = antiTamper,
            antiHook = antiHook,
            rootDetection = rootDetection,
            emulatorDetection = emulatorDetection,
            runtimeProtection = runtimeProtection,
            playIntegrity = playIntegrity,
            stringEncryption = stringEncryption,
            resourceEncryption = resourceEncryption,
            sslPinning = sslPinning,
            nativeProtection = nativeProtection,
            constantEncryption = constantEncryption,
            bytecodeObfuscation = bytecodeObfuscation,
            stripMetadata = stripMetadata,
            obfuscationIntensity = obfuscationIntensity,
            protectPackages = protectPackages,
        )
    }

    companion object {
        fun builder(): Builder = Builder()

        /** Sensible defaults for debug builds (lighter protection). */
        fun debugDefaults(): ShieldConfig = builder()
            .playIntegrity(false)
            .obfuscationIntensity(1)
            .build()

        /** Aggressive defaults for release. */
        fun releaseDefaults(): ShieldConfig = builder()
            .playIntegrity(true)
            .obfuscationIntensity(2)
            .build()
    }
}

/**
 * JSON encode/decode for [ShieldConfig].
 */
object ShieldConfigCodec {
    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    fun encode(config: ShieldConfig): String = json.encodeToString(config)

    fun decode(raw: String): ShieldConfig = json.decodeFromString(raw)
}
