package com.androidshield.plugin.extension

import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

/**
 * Gradle DSL for AndroidShield build-time and runtime feature flags.
 *
 * Example:
 * ```
 * androidShield {
 *   antiDebug.set(true)
 *   stringEncryption.set(true)
 *   obfuscationIntensity.set(2)
 *   protectPackages.add("com.example.app")
 * }
 * ```
 */
abstract class AndroidShieldExtension {
    abstract val enabled: Property<Boolean>

    abstract val antiDebug: Property<Boolean>
    abstract val antiTamper: Property<Boolean>
    abstract val antiHook: Property<Boolean>
    abstract val rootDetection: Property<Boolean>
    abstract val emulatorDetection: Property<Boolean>
    abstract val runtimeProtection: Property<Boolean>
    abstract val playIntegrity: Property<Boolean>
    abstract val stringEncryption: Property<Boolean>
    abstract val resourceEncryption: Property<Boolean>
    abstract val sslPinning: Property<Boolean>
    abstract val nativeProtection: Property<Boolean>

    abstract val constantEncryption: Property<Boolean>
    abstract val bytecodeObfuscation: Property<Boolean>
    abstract val stripMetadata: Property<Boolean>
    abstract val deadCodeInsertion: Property<Boolean>
    abstract val opaquePredicates: Property<Boolean>
    abstract val controlFlowFlattening: Property<Boolean>
    abstract val mappingProtection: Property<Boolean>
    abstract val releaseValidation: Property<Boolean>

    /** 1 = light, 2 = medium, 3 = aggressive transforms. */
    abstract val obfuscationIntensity: Property<Int>

    /** Packages to instrument; empty means application Id / host packages. */
    abstract val protectPackages: ListProperty<String>

    /** Asset path globs relative to assets/ (e.g. shield folder, pem, json). */
    abstract val encryptAssetPatterns: ListProperty<String>

    /** Fail the release build when validation detects misconfiguration. */
    abstract val failOnValidationError: Property<Boolean>

    init {
        enabled.convention(true)
        antiDebug.convention(true)
        antiTamper.convention(true)
        antiHook.convention(true)
        rootDetection.convention(true)
        emulatorDetection.convention(true)
        runtimeProtection.convention(true)
        playIntegrity.convention(false)
        stringEncryption.convention(true)
        resourceEncryption.convention(true)
        sslPinning.convention(true)
        nativeProtection.convention(true)
        constantEncryption.convention(true)
        bytecodeObfuscation.convention(true)
        stripMetadata.convention(true)
        deadCodeInsertion.convention(true)
        opaquePredicates.convention(true)
        controlFlowFlattening.convention(false)
        mappingProtection.convention(true)
        releaseValidation.convention(true)
        obfuscationIntensity.convention(1)
        protectPackages.convention(emptyList())
        encryptAssetPatterns.convention(listOf("shield/**", "**/*.pem", "**/*.json"))
        failOnValidationError.convention(true)
    }
}