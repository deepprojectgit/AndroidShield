plugins {
    `kotlin-dsl`
}

group = "com.androidshield.buildlogic"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    compileOnly(libs.android.gradle.plugin)
    compileOnly(libs.kotlin.gradle.plugin)
    implementation(libs.plugins.detekt.toDep())
    implementation(libs.plugins.ktlint.toDep())
    implementation(libs.plugins.maven.publish.toDep())
}

fun Provider<PluginDependency>.toDep() =
    map { "${it.pluginId}:${it.pluginId}.gradle.plugin:${it.version}" }

gradlePlugin {
    plugins {
        register("androidLibrary") {
            id = "androidshield.android.library"
            implementationClass = "com.androidshield.buildlogic.AndroidLibraryConventionPlugin"
        }
        register("androidApplication") {
            id = "androidshield.android.application"
            implementationClass = "com.androidshield.buildlogic.AndroidApplicationConventionPlugin"
        }
        register("jvmLibrary") {
            id = "androidshield.jvm.library"
            implementationClass = "com.androidshield.buildlogic.JvmLibraryConventionPlugin"
        }
        register("publishing") {
            id = "androidshield.publishing"
            implementationClass = "com.androidshield.buildlogic.PublishingConventionPlugin"
        }
        register("quality") {
            id = "androidshield.quality"
            implementationClass = "com.androidshield.buildlogic.QualityConventionPlugin"
        }
    }
}
