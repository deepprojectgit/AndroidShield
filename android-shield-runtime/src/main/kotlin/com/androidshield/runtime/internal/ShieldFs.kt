package com.androidshield.runtime.internal

import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File

/**
 * Shared filesystem / package helpers for detectors (no reflection).
 */
internal object ShieldFs {
    fun anyExists(paths: Array<String>): String? =
        paths.firstOrNull { File(it).exists() }

    fun readFirstLine(path: String): String? =
        runCatching { File(path).bufferedReader().use { it.readLine() } }.getOrNull()

    fun readText(path: String): String? =
        runCatching { File(path).readText() }.getOrNull()

    fun isDebuggable(context: Context): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    fun packageInstalled(context: Context, packageName: String): Boolean =
        runCatching {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        }.getOrDefault(false)
}
