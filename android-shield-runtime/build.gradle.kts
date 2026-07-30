plugins {
    id("androidshield.android.library")
    id("androidshield.publishing")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.androidshield.runtime"
}

dependencies {
    api(project(":android-shield-core"))
    api(project(":android-shield-annotations"))
    implementation(project(":android-shield-native"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.security.crypto)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.play.integrity)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.robolectric)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(project(":android-shield-testing"))

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.truth)
}
