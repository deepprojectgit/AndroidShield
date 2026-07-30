package com.androidshield.buildlogic

import com.vanniktech.maven.publish.MavenPublishBaseExtension
import com.vanniktech.maven.publish.SonatypeHost
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

/**
 * Maven Central–ready publishing via com.vanniktech.maven.publish.
 *
 * Requires a **public** GitHub repository for the free OSS Central path and
 * `io.github.*` namespace verification.
 *
 * Group: [androidshield.groupId]
 * Version: [androidshield.version]
 *
 * Credentials (CI / ~/.gradle/gradle.properties):
 * - mavenCentralUsername / mavenCentralPassword
 * - signingInMemoryKey (+ optional Id / Password)
 */
class PublishingConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply("com.vanniktech.maven.publish")

            val groupIdValue = providers.gradleProperty("androidshield.groupId")
                .orElse("io.github.deepprojectgit.androidshield")
            val versionValue = providers.gradleProperty("androidshield.version")
                .orElse("0.1.0-SNAPSHOT")

            group = groupIdValue.get()
            version = versionValue.get()

            extensions.configure<MavenPublishBaseExtension> {
                coordinates(
                    groupId = groupIdValue.get(),
                    artifactId = project.name,
                    version = versionValue.get(),
                )

                // Central Portal + auto-release after upload (non-SNAPSHOT).
                publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
                signAllPublications()

                pom {
                    name.set(project.name)
                    description.set(
                        project.findProperty("POM_DESCRIPTION")?.toString()
                            ?: "AndroidShield protection module",
                    )
                    inceptionYear.set("2026")
                    url.set("https://github.com/deepprojectgit/AndroidShield")
                    licenses {
                        license {
                            name.set("Apache License 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                            distribution.set("repo")
                        }
                    }
                    developers {
                        developer {
                            id.set("deepprojectgit")
                            name.set("AndroidShield Contributors")
                            url.set("https://github.com/deepprojectgit")
                        }
                    }
                    scm {
                        url.set("https://github.com/deepprojectgit/AndroidShield")
                        connection.set("scm:git:git://github.com/deepprojectgit/AndroidShield.git")
                        developerConnection.set(
                            "scm:git:ssh://git@github.com/deepprojectgit/AndroidShield.git",
                        )
                    }
                }
            }
        }
    }
}
