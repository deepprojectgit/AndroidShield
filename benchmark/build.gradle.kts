plugins {
    id("androidshield.android.library")
}

android {
    namespace = "com.androidshield.benchmark"
}

dependencies {
    implementation(project(":android-shield-runtime"))
    implementation(libs.androidx.benchmark.junit4)
    androidTestImplementation(libs.androidx.benchmark.junit4)
    androidTestImplementation(libs.androidx.junit)
}
