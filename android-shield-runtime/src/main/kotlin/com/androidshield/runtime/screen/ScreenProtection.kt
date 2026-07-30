package com.androidshield.runtime.screen

import android.app.Activity
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.view.WindowManager
import com.androidshield.core.model.Severity
import com.androidshield.core.model.Threat
import com.androidshield.runtime.detector.threat

/**
 * Screen capture / overlay / tapjacking protections and detectors.
 */
object ScreenProtection {
    /**
     * Applies [WindowManager.LayoutParams.FLAG_SECURE] to prevent screenshots / recents previews.
     */
    @JvmStatic
    fun enableFlagSecure(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    @JvmStatic
    fun disableFlagSecure(activity: Activity) {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    /**
     * Detects accessibility services that can observe UI (possible abuse).
     */
    @JvmStatic
    fun detectAccessibilityAbuse(context: Context): List<Threat> {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return emptyList()
        if (enabled.isBlank()) return emptyList()
        return listOf(
            threat(
                id = "screen.accessibility_enabled",
                title = "Accessibility services enabled",
                severity = Severity.MEDIUM,
                description = "Enabled services: $enabled",
                recommendation = "Verify user-consent services; block screens with FLAG_SECURE when untrusted",
            ),
        )
    }

    /**
     * Best-effort MediaProjection / overlay heuristics.
     */
    @JvmStatic
    fun detectOverlayThreats(context: Context): List<Threat> {
        val threats = mutableListOf<Threat>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (Settings.canDrawOverlays(context)) {
                threats += threat(
                    id = "screen.overlay_permission",
                    title = "Draw-over-apps permission granted",
                    severity = Severity.MEDIUM,
                    description = "SYSTEM_ALERT_WINDOW capability present for this or another app policy surface",
                    recommendation = "Use filterTouchesWhenObscured and ignore obscured touches on sensitive UI",
                )
            }
        }
        return threats
    }

    /**
     * Marks a view hierarchy to ignore touches when obscured (tapjacking mitigation).
     */
    @JvmStatic
    fun enableTapjackingGuards(activity: Activity) {
        activity.window.decorView.filterTouchesWhenObscured = true
    }
}
