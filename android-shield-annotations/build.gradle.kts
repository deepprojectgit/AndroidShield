plugins {
    id("androidshield.jvm.library")
    id("androidshield.publishing")
}

dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(libs.kotlin.test)
}
