package com.androidshield.buildlogic

import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.CommonExtension
import com.android.build.api.dsl.LibraryExtension
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

internal val Project.libs: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("libs")

internal fun Project.configureKotlinAndroid(commonExtension: CommonExtension<*, *, *, *, *, *>) {
    val compileSdkVersion = libs.findVersion("compileSdk").get().requiredVersion.toInt()
    val minSdkVersion = libs.findVersion("minSdk").get().requiredVersion.toInt()

    commonExtension.apply {
        compileSdk = compileSdkVersion
        defaultConfig {
            minSdk = minSdkVersion
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }
    }

    configureKotlinJvm()
}

internal fun Project.configureKotlinJvm() {
    tasks.withType<KotlinCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            freeCompilerArgs.addAll(
                "-Xjvm-default=all",
                "-opt-in=kotlin.RequiresOptIn",
            )
        }
    }
}

internal fun Project.configureAndroidLibrary() {
    pluginManager.apply("com.android.library")
    pluginManager.apply("org.jetbrains.kotlin.android")
    extensions.configure<LibraryExtension> {
        configureKotlinAndroid(this)
        defaultConfig {
            consumerProguardFiles("consumer-rules.pro")
        }
        buildTypes {
            release {
                isMinifyEnabled = false
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
        }
    }
}

internal fun Project.configureAndroidApplication() {
    pluginManager.apply("com.android.application")
    pluginManager.apply("org.jetbrains.kotlin.android")
    extensions.configure<ApplicationExtension> {
        configureKotlinAndroid(this)
        defaultConfig {
            targetSdk = libs.findVersion("targetSdk").get().requiredVersion.toInt()
        }
        buildTypes {
            release {
                isMinifyEnabled = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
            debug {
                isMinifyEnabled = false
            }
        }
    }
}
