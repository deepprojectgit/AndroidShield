package com.androidshield.sample

import android.app.Application
import com.androidshield.core.config.ShieldConfig
import com.androidshield.runtime.api.AndroidShield

/**
 * Sample host — initializes AndroidShield with a representative feature set.
 *
 * Play Integrity stays off so the demo works without a cloud project number.
 */
class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AndroidShield.initialize(
            context = this,
            config =
            ShieldConfig.Builder()
                .antiDebug(true)
                .antiTamper(true)
                .antiHook(true)
                .rootDetection(true)
                .emulatorDetection(true)
                .runtimeProtection(true)
                .nativeProtection(true)
                .sslPinning(false)
                .playIntegrity(false)
                .build(),
        )
    }
}
