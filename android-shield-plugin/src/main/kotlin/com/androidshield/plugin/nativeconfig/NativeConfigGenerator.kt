package com.androidshield.plugin.nativeconfig

/**
 * Emits JSON config consumed later by the native module (Phase 5).
 */
object NativeConfigGenerator {
    fun generate(
        antiDebug: Boolean,
        antiHook: Boolean,
        antiTamper: Boolean,
        nativeProtection: Boolean,
        buildFingerprint: String,
    ): String = buildString {
        appendLine("{")
        appendLine("""  "version": 1,""")
        appendLine("""  "antiDebug": $antiDebug,""")
        appendLine("""  "antiHook": $antiHook,""")
        appendLine("""  "antiTamper": $antiTamper,""")
        appendLine("""  "nativeProtection": $nativeProtection,""")
        appendLine("""  "buildFingerprint": "$buildFingerprint"""")
        appendLine("}")
    }
}
