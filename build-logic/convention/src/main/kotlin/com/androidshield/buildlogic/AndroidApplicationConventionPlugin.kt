package com.androidshield.buildlogic

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Convention plugin for Android application modules.
 */
class AndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            configureAndroidApplication()
            pluginManager.apply("androidshield.quality")
        }
    }
}
