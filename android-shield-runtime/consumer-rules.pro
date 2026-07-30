# Consumer ProGuard / R8 rules for android-shield-runtime.
-keep class com.androidshield.runtime.api.AndroidShield { *; }
-keep class com.androidshield.runtime.crypto.** { *; }
-keep class com.androidshield.runtime.storage.SecureStorage { *; }
-keep class com.androidshield.runtime.network.SslPinning { *; }
-keep class com.androidshield.runtime.play.PlayIntegrityClient { *; }
-keep class com.androidshield.core.model.** { *; }
-keep class com.androidshield.core.config.** { *; }
-keep class com.androidshield.core.integrity.** { *; }
