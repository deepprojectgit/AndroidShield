package com.androidshield.runtime.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Android Keystore–backed secure preferences and file storage (AES-GCM via Jetpack Security).
 */
class SecureStorage private constructor(
    private val preferences: SharedPreferences,
    private val filesDir: File,
    private val masterKey: MasterKey,
    private val context: Context,
) {
    fun putString(key: String, value: String) {
        preferences.edit().putString(key, value).apply()
    }

    fun getString(key: String, default: String? = null): String? =
        preferences.getString(key, default)

    fun remove(key: String) {
        preferences.edit().remove(key).apply()
    }

    fun contains(key: String): Boolean = preferences.contains(key)

    /**
     * Writes [content] to an [EncryptedFile] under the app's shielded files directory.
     */
    fun writeSecureFile(name: String, content: ByteArray) {
        val file = File(filesDir, name)
        if (file.exists()) file.delete()
        val encrypted = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
        encrypted.openFileOutput().use { it.write(content) }
    }

    fun readSecureFile(name: String): ByteArray? {
        val file = File(filesDir, name)
        if (!file.exists()) return null
        val encrypted = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
        return encrypted.openFileInput().use { it.readBytes() }
    }

    fun writeSecureText(name: String, text: String) {
        writeSecureFile(name, text.toByteArray(StandardCharsets.UTF_8))
    }

    fun readSecureText(name: String): String? =
        readSecureFile(name)?.toString(StandardCharsets.UTF_8)

    companion object {
        private const val PREFS_NAME = "android_shield_secure_prefs"

        @JvmStatic
        fun create(context: Context): SecureStorage {
            val app = context.applicationContext
            val masterKey = MasterKey.Builder(app)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val prefs = EncryptedSharedPreferences.create(
                app,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            val dir = File(app.filesDir, "androidshield/secure").also { it.mkdirs() }
            return SecureStorage(prefs, dir, masterKey, app)
        }
    }
}
