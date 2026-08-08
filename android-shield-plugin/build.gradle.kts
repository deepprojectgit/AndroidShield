plugins {
    `java-gradle-plugin`
    `kotlin-dsl`
    id("androidshield.publishing")
}

group = providers.gradleProperty("androidshield.groupId")
    .orElse("io.github.deepprojectgit.androidshield")
    .get()
version = providers.gradleProperty("androidshield.version")
    .orElse("0.1.2")
    .get()

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    compileOnly(libs.android.gradle.plugin.api)
    compileOnly(libs.android.gradle.plugin)
    compileOnly(libs.kotlin.gradle.plugin)

    implementation(libs.asm)
    implementation(libs.asm.commons)
    implementation(libs.asm.tree)
    implementation(libs.asm.util)
    implementation(project(":android-shield-core"))
    implementation(project(":android-shield-annotations"))

    testImplementation(libs.junit)
    testImplementation(libs.truth)
    testImplementation(gradleTestKit())
}

gradlePlugin {
    plugins {
        create("androidShield") {
            id = "io.github.deepprojectgit.androidshield"
            implementationClass = "com.androidshield.plugin.AndroidShieldPlugin"
            displayName = "AndroidShield"
            description = "Build-time Android application protection (bytecode, encryption, integrity)."
        }
    }
}
