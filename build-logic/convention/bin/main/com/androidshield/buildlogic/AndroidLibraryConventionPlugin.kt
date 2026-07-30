package com.androidshield.buildlogic

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Convention plugin for Android library modules (AAR).
 */
class AndroidLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            configureAndroidLibrary()
            pluginManager.apply("androidshield.quality")
        }
    }
}
