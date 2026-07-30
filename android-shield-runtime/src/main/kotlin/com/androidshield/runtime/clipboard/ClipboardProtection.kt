package com.androidshield.runtime.clipboard

import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Monitors clipboard content and optionally clears sensitive data after a delay.
 */
class ClipboardProtection(
    context: Context,
    private val clearDelayMs: Long = DEFAULT_CLEAR_DELAY_MS,
) {
    private val appContext = context.applicationContext
    private val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val handler = Handler(Looper.getMainLooper())
    private val monitoring = AtomicBoolean(false)
    private var lastSensitive: String? = null

    private val listener = ClipboardManager.OnPrimaryClipChangedListener {
        if (!monitoring.get()) return@OnPrimaryClipChangedListener
        val text = clipboard.primaryClip
            ?.getItemAt(0)
            ?.coerceToText(appContext)
            ?.toString()
            ?: return@OnPrimaryClipChangedListener
        if (looksSensitive(text)) {
            lastSensitive = text
            handler.postDelayed({ clearIfStillSensitive(text) }, clearDelayMs)
        }
    }

    fun start() {
        if (monitoring.compareAndSet(false, true)) {
            clipboard.addPrimaryClipChangedListener(listener)
        }
    }

    fun stop() {
        if (monitoring.compareAndSet(true, false)) {
            clipboard.removePrimaryClipChangedListener(listener)
            handler.removeCallbacksAndMessages(null)
        }
    }

    fun clearClipboard() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            @Suppress("DEPRECATION")
            clipboard.text = ""
        }
    }

    fun lastSensitiveSample(): String? = lastSensitive?.take(4)?.plus("…")

    private fun clearIfStillSensitive(expected: String) {
        val current = clipboard.primaryClip
            ?.getItemAt(0)
            ?.coerceToText(appContext)
            ?.toString()
        if (current == expected) {
            clearClipboard()
        }
    }

    companion object {
        private const val DEFAULT_CLEAR_DELAY_MS = 30_000L

        fun looksSensitive(text: String): Boolean {
            val lower = text.lowercase()
            return lower.length >= 8 && (
                lower.contains("password") ||
                    lower.contains("otp") ||
                    lower.contains("token") ||
                    lower.contains("cvv") ||
                    Regex("""\b\d{13,19}\b""").containsMatchIn(text) // crude PAN-like
                )
        }
    }
}
