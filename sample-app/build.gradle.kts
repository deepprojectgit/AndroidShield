plugins {
    id("androidshield.android.application")
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.androidshield.sample"
    defaultConfig {
        applicationId = "com.androidshield.sample"
        versionCode = 1
        versionName = "0.1.0-SNAPSHOT"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(project(":android-shield-runtime"))
    implementation(project(":android-shield-annotations"))
    implementation(project(":android-shield-native"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

// Apply published plugin in consuming apps:
// plugins { id("com.androidshield.gradle") version "<version>" }
// In-repo verification of the plugin is covered by :android-shield-plugin:test.
