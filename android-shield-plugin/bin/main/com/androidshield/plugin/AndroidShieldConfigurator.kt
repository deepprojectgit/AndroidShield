package com.androidshield.plugin

import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.ApplicationVariant
import com.android.build.api.variant.Variant
import com.androidshield.plugin.crypto.CryptoMaterialStore
import com.androidshield.plugin.extension.AndroidShieldExtension
import com.androidshield.plugin.task.EncryptResourcesTask
import com.androidshield.plugin.task.GenerateSecurityReportTask
import com.androidshield.plugin.task.GenerateShieldArtifactsTask
import com.androidshield.plugin.task.ProtectMappingTask
import com.androidshield.plugin.transform.ShieldAsmFactory
import org.gradle.api.Project
import org.gradle.api.tasks.TaskProvider
import java.util.Base64

/**
 * Wires AGP instrumentation and AndroidShield Gradle tasks for a project.
 */
internal object AndroidShieldConfigurator {
    fun configure(project: Project, extension: AndroidShieldExtension) {
        project.afterEvaluate {
            if (!extension.enabled.get()) {
                project.logger.lifecycle("AndroidShield disabled via androidShield.enabled=false")
                return@afterEvaluate
            }
            val material = CryptoMaterialStore.obtain(project)
            val scrambledB64 = Base64.getEncoder().encodeToString(material.scrambledKey)
            val seedB64 = Base64.getEncoder().encodeToString(material.seed)

            val androidComponents =
                project.extensions.findByType(AndroidComponentsExtension::class.java)
            if (androidComponents == null) {
                project.logger.warn("AndroidShield: AndroidComponentsExtension not found")
                return@afterEvaluate
            }

            // onVariants must be registered before variant locking; if too late, register from apply without afterEvaluate
            project.logger.lifecycle("AndroidShield configuring tasks for project {}", project.path)
            registerTopLevelTasks(project, extension, scrambledB64, seedB64)
        }

        // Instrumentation must be registered early (not in afterEvaluate)
        val androidComponents =
            project.extensions.findByType(AndroidComponentsExtension::class.java)
        if (androidComponents != null) {
            wireInstrumentation(project, extension, androidComponents)
        } else {
            project.pluginManager.withPlugin("com.android.application") {
                project.extensions.findByType(AndroidComponentsExtension::class.java)?.let {
                    wireInstrumentation(project, extension, it)
                }
            }
            project.pluginManager.withPlugin("com.android.library") {
                project.extensions.findByType(AndroidComponentsExtension::class.java)?.let {
                    wireInstrumentation(project, extension, it)
                }
            }
        }
    }

    private fun wireInstrumentation(
        project: Project,
        extension: AndroidShieldExtension,
        androidComponents: AndroidComponentsExtension<*, *, *>,
    ) {
        val material = CryptoMaterialStore.obtain(project)
        val scrambledB64 = Base64.getEncoder().encodeToString(material.scrambledKey)
        val seedB64 = Base64.getEncoder().encodeToString(material.seed)

        androidComponents.onVariants { variant ->
            configureVariant(project, extension, variant, scrambledB64, seedB64)
        }
    }

    private fun registerTopLevelTasks(
        project: Project,
        extension: AndroidShieldExtension,
        scrambledB64: String,
        seedB64: String,
    ) {
        if (project.tasks.findByName("androidShieldValidate") == null) {
            project.tasks.register("androidShieldValidate") {
                group = "androidshield"
                description = "Prints AndroidShield configuration summary"
                doLast {
                    logger.lifecycle(
                        "AndroidShield: stringEncryption={}, intensity={}, keyReady={}",
                        extension.stringEncryption.get(),
                        extension.obfuscationIntensity.get(),
                        scrambledB64.isNotEmpty() && seedB64.isNotEmpty(),
                    )
                }
            }
        }
    }

    private fun configureVariant(
        project: Project,
        extension: AndroidShieldExtension,
        variant: Variant,
        scrambledB64: String,
        seedB64: String,
    ) {
        val variantName = variant.name
        val capitalized = variantName.replaceFirstChar { it.uppercase() }

        if (extension.bytecodeObfuscation.get() || extension.stringEncryption.get()) {
            variant.instrumentation.transformClassesWith(
                ShieldAsmFactory::class.java,
                InstrumentationScope.PROJECT,
            ) { params ->
                params.stringEncryption.set(extension.stringEncryption)
                params.stripMetadata.set(extension.stripMetadata)
                params.deadCodeInsertion.set(extension.deadCodeInsertion)
                params.opaquePredicates.set(extension.opaquePredicates)
                params.controlFlowFlattening.set(extension.controlFlowFlattening)
                params.obfuscationIntensity.set(extension.obfuscationIntensity)
                params.scrambledKeyBase64.set(scrambledB64)
                params.seedBase64.set(seedB64)
                params.protectPackages.set(extension.protectPackages)
            }
            variant.instrumentation.setAsmFramesComputationMode(
                FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS,
            )
        }

        val artifactsDir = project.layout.buildDirectory.dir("androidshield/$variantName")
        val assetsOut = project.layout.buildDirectory.dir("androidshield/$variantName/encrypted-assets")

        val packageNameProvider = if (variant is ApplicationVariant) {
            variant.applicationId
        } else {
            project.provider {
                project.group.toString().ifBlank { "com.androidshield.generated" }
            }
        }

        val generateArtifacts =
            project.tasks.register(
                "generateShieldArtifacts$capitalized",
                GenerateShieldArtifactsTask::class.java,
            ) {
                group = "androidshield"
                description = "Generates integrity metadata, secrets, R8 rules for $variantName"
                this.variantName.set(variantName)
                this.packageName.set(packageNameProvider)
                stringEncryption.set(extension.stringEncryption)
                resourceEncryption.set(extension.resourceEncryption)
                antiDebug.set(extension.antiDebug)
                antiHook.set(extension.antiHook)
                antiTamper.set(extension.antiTamper)
                nativeProtection.set(extension.nativeProtection)
                mappingProtection.set(extension.mappingProtection)
                protectPackages.set(extension.protectPackages)
                fingerprintInputs.from(project.layout.projectDirectory.dir("src"))
                outputDir.set(artifactsDir)
                integrityMetadataFile.set(artifactsDir.map { it.file("integrity.json") })
                fingerprintFile.set(artifactsDir.map { it.file("fingerprint.txt") })
                r8RulesFile.set(artifactsDir.map { it.file("androidshield-r8.pro") })
                nativeConfigFile.set(artifactsDir.map { it.file("native-config.json") })
                cryptoMaterialFile.set(
                    project.layout.buildDirectory.file("androidshield/keys/material.txt"),
                )
                secretsJavaFile.set(
                    artifactsDir.map { it.file("src/BuildShieldSecrets.java") },
                )
            }

        if (extension.resourceEncryption.get()) {
            val encryptTask =
                project.tasks.register(
                    "encryptShieldResources$capitalized",
                    EncryptResourcesTask::class.java,
                ) {
                    group = "androidshield"
                    description = "Encrypts configured assets for $variantName"
                    dependsOn(generateArtifacts)
                    inputAssets.from(project.layout.projectDirectory.dir("src/main/assets"))
                    patterns.set(extension.encryptAssetPatterns)
                    cryptoMaterialFile.set(
                        project.layout.buildDirectory.file("androidshield/keys/material.txt"),
                    )
                    outputAssets.set(assetsOut)
                }
            wireAssetMerge(project, variantName, encryptTask)
        }

        val isDebuggable = variantName.contains("debug", ignoreCase = true)
        val minifyGuess = !isDebuggable

        project.tasks.register(
            "generateShieldReport$capitalized",
            GenerateSecurityReportTask::class.java,
        ) {
            group = "androidshield"
            description = "Writes AndroidShield security report for $variantName"
            dependsOn(generateArtifacts)
            extensionRef.set(extension)
            minifyEnabled.set(minifyGuess)
            debuggable.set(isDebuggable)
            failOnValidationError.set(!isDebuggable && extension.failOnValidationError.get())
            reportFile.set(artifactsDir.map { it.file("security-report.json") })
        }

        if (extension.mappingProtection.get()) {
            project.tasks.register(
                "protectShieldMapping$capitalized",
                ProtectMappingTask::class.java,
            ) {
                group = "androidshield"
                description = "Scrambles R8 mapping outputs for $variantName"
                mappingFiles.from(
                    project.layout.buildDirectory.dir("outputs/mapping/$variantName"),
                )
                protectedDir.set(artifactsDir.map { it.dir("protected-mapping") })
                mustRunAfter(project.tasks.matching { it.name == "minify${capitalized}WithR8" })
            }
        }

        project.tasks.matching {
            it.name == "pre${capitalized}Build" || it.name == "preBuild"
        }.configureEach {
            dependsOn(generateArtifacts)
        }
    }

    private fun wireAssetMerge(
        project: Project,
        variantName: String,
        encryptTask: TaskProvider<EncryptResourcesTask>,
    ) {
        val mergeTaskName = "merge${variantName.replaceFirstChar { it.uppercase() }}Assets"
        project.tasks.matching { it.name == mergeTaskName }.configureEach {
            dependsOn(encryptTask)
        }
    }
}
