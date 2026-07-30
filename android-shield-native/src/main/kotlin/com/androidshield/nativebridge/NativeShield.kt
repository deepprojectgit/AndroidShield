package com.androidshield.nativebridge

/**
 * JNI façade for native protection routines.
 *
 * Provides anti-debug / anti-hook / memory validation, checksums, key unscramble,
 * and AES-GCM decrypt (delegates AEAD to [com.androidshield.core.crypto.AesGcmCipher]).
 */
object NativeShield {
    private val loaded: Boolean =
        try {
            System.loadLibrary("androidshield")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }

    @JvmStatic
    fun isAvailable(): Boolean = loaded

    /**
     * Combined self-check bitmask:
     * bits 0–7 debug, 8–15 hook, 16–23 memory. `0` means clean.
     */
    @JvmStatic
    external fun nativeSelfCheck(): Int

    @JvmStatic
    external fun nativeCheckDebugger(): Int

    @JvmStatic
    external fun nativeCheckHooks(): Int

    @JvmStatic
    external fun nativeCheckMemory(): Int

    @JvmStatic
    external fun nativeChecksum(payload: ByteArray): Long

    @JvmStatic
    external fun nativeSha256(payload: ByteArray): ByteArray?

    @JvmStatic
    external fun nativeUnscrambleKey(scrambled: ByteArray, seed: ByteArray): ByteArray?

    /**
     * Decrypts AES-256-GCM. Argument order matches [com.androidshield.core.crypto.AesGcmCipher.decrypt].
     */
    @JvmStatic
    external fun nativeDecryptAesGcm(cipherText: ByteArray, iv: ByteArray, key: ByteArray): ByteArray?

    /**
     * Safe wrapper returning 0 when the library is unavailable.
     */
    @JvmStatic
    fun selfCheck(): Int = if (loaded) runCatching { nativeSelfCheck() }.getOrDefault(-1) else -1

    @JvmStatic
    fun checkDebugger(): Int =
        if (loaded) runCatching { nativeCheckDebugger() }.getOrDefault(-1) else -1

    @JvmStatic
    fun checkHooks(): Int =
        if (loaded) runCatching { nativeCheckHooks() }.getOrDefault(-1) else -1

    @JvmStatic
    fun checkMemory(): Int =
        if (loaded) runCatching { nativeCheckMemory() }.getOrDefault(-1) else -1

    data class NativeFindings(
        val debuggerFlags: Int,
        val hookFlags: Int,
        val memoryFlags: Int,
    ) {
        val isClean: Boolean get() = debuggerFlags == 0 && hookFlags == 0 && memoryFlags == 0
    }

    @JvmStatic
    fun evaluate(): NativeFindings {
        if (!loaded) {
            return NativeFindings(debuggerFlags = -1, hookFlags = -1, memoryFlags = -1)
        }
        val packed = selfCheck()
        if (packed < 0) {
            return NativeFindings(-1, -1, -1)
        }
        return NativeFindings(
            debuggerFlags = packed and 0xff,
            hookFlags = (packed shr 8) and 0xff,
            memoryFlags = (packed shr 16) and 0xff,
        )
    }
}
