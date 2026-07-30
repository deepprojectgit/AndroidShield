plugins {
    id("androidshield.jvm.library")
    application
    id("androidshield.publishing")
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("com.androidshield.cli.MainKt")
}

dependencies {
    implementation(project(":android-shield-core"))
    implementation(libs.clikt)
    implementation(libs.mordant)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(project(":android-shield-testing"))
}
