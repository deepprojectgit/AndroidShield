plugins {
    id("androidshield.jvm.library")
}

dependencies {
    api(project(":android-shield-core"))
    api(libs.junit)
    api(libs.truth)
    api(libs.kotlin.test)
}
