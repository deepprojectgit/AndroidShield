package com.androidshield.plugin.task

import com.androidshield.core.crypto.KeyScrambler
import com.androidshield.core.model.Severity
import com.androidshield.plugin.crypto.BuildCryptoMaterial
import com.androidshield.plugin.crypto.CryptoMaterialStore
import com.androidshield.plugin.extension.AndroidShieldExtension
import com.androidshield.plugin.integrity.IntegrityMetadataFactory
import com.androidshield.plugin.nativeconfig.NativeConfigGenerator
import com.androidshield.plugin.r8.R8RulesGenerator
import com.androidshield.plugin.report.BuildSecurityReporter
import com.androidshield.plugin.validation.ReleaseValidator
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.util.Base64

/**
 * Generates integrity metadata, R8 rules, native config, and BuildShieldSecrets using shared crypto material.
 */
abstract class GenerateShieldArtifactsTask : DefaultTask() {
    @get:Input
    abstract val variantName: Property<String>

    @get:Input
    abstract val packageName: Property<String>

    @get:Input
    abstract val stringEncryption: Property<Boolean>

    @get:Input
    abstract val resourceEncryption: Property<Boolean>

    @get:Input
    abstract val antiDebug: Property<Boolean>

    @get:Input
    abstract val antiHook: Property<Boolean>

    @get:Input
    abstract val antiTamper: Property<Boolean>

    @get:Input
    abstract val nativeProtection: Property<Boolean>

    @get:Input
    abstract val mappingProtection: Property<Boolean>

    @get:Input
    abstract val protectPackages: ListProperty<String>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fingerprintInputs: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:OutputFile
    abstract val integrityMetadataFile: RegularFileProperty

    @get:OutputFile
    abstract val fingerprintFile: RegularFileProperty

    @get:OutputFile
    abstract val r8RulesFile: RegularFileProperty

    @get:OutputFile
    abstract val nativeConfigFile: RegularFileProperty

    @get:OutputFile
    abstract val secretsJavaFile: RegularFileProperty

    @get:OutputFile
    abstract val cryptoMaterialFile: RegularFileProperty

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    @TaskAction
    fun generate() {
        outputDir.get().asFile.mkdirs()
        val material = CryptoMaterialStore.obtain(project)
        cryptoMaterialFile.get().asFile.parentFile.mkdirs()
        cryptoMaterialFile.get().asFile.writeText(
            buildString {
                appendLine(Base64.getEncoder().encodeToString(material.scrambledKey))
                appendLine(Base64.getEncoder().encodeToString(material.seed))
            },
        )

        val fingerprint = IntegrityMetadataFactory.fingerprint(
            packageName = packageName.get(),
            variantName = variantName.get(),
            materials = fingerprintInputs.files.toList() + listOf(cryptoMaterialFile.get().asFile),
        )
        fingerprintFile.get().asFile.writeText(fingerprint)

        val metadata = IntegrityMetadataFactory.create(
            packageName = packageName.get(),
            variantName = variantName.get(),
            fingerprint = fingerprint,
            stringEncryption = stringEncryption.get(),
            resourceEncryption = resourceEncryption.get(),
        )
        integrityMetadataFile.get().asFile.writeText(json.encodeToString(metadata))

        r8RulesFile.get().asFile.writeText(
            R8RulesGenerator.generate(protectPackages.get(), mappingProtection.get()),
        )

        nativeConfigFile.get().asFile.writeText(
            NativeConfigGenerator.generate(
                antiDebug = antiDebug.get(),
                antiHook = antiHook.get(),
                antiTamper = antiTamper.get(),
                nativeProtection = nativeProtection.get(),
                buildFingerprint = fingerprint,
            ),
        )

        secretsJavaFile.get().asFile.parentFile.mkdirs()
        secretsJavaFile.get().asFile.writeText(renderSecretsJava(material))
        logger.lifecycle("AndroidShield artifacts generated for variant {}", variantName.get())
    }

    private fun renderSecretsJava(material: BuildCryptoMaterial): String {
        val pkg = packageName.get().ifBlank { "com.androidshield.generated" }
        fun bytesLiteral(bytes: ByteArray): String =
            bytes.joinToString(prefix = "new byte[]{", postfix = "}") { b -> "(byte)${b.toInt()}" }

        return """
            |package $pkg;
            |
            |/**
            | * GENERATED by AndroidShield — do not edit.
            | */
            |public final class BuildShieldSecrets {
            |    private BuildShieldSecrets() {}
            |
            |    public static final byte[] SCRAMBLED_KEY = ${bytesLiteral(material.scrambledKey)};
            |    public static final byte[] SEED = ${bytesLiteral(material.seed)};
            |
            |    static {
            |        com.androidshield.runtime.crypto.BuildSecrets.install(SCRAMBLED_KEY, SEED);
            |    }
            |
            |    public static void ensureInstalled() {
            |        // touch class init
            |    }
            |}
            |
        """.trimMargin()
    }
}

/**
 * Encrypts matching asset files into the AndroidShield assets output tree.
 */
abstract class EncryptResourcesTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputAssets: ConfigurableFileCollection

    @get:Input
    abstract val patterns: ListProperty<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val cryptoMaterialFile: RegularFileProperty

    @get:OutputDirectory
    abstract val outputAssets: DirectoryProperty

    @TaskAction
    fun encrypt() {
        val materialFile = cryptoMaterialFile.get().asFile
        check(materialFile.exists()) { "Crypto material missing — run generateShieldArtifacts first" }
        val lines = materialFile.readLines()
        val scrambled = Base64.getDecoder().decode(lines[0])
        val seed = Base64.getDecoder().decode(lines[1])
        val key = KeyScrambler.unscramble(scrambled, seed)
        val material = BuildCryptoMaterial(key = key, seed = seed, scrambledKey = scrambled)

        val outRoot = outputAssets.get().asFile
        if (outRoot.exists()) outRoot.deleteRecursively()
        outRoot.mkdirs()

        val patternMatchers = patterns.get().map { globToRegex(it) }
        inputAssets.files.forEach { root ->
            if (!root.exists()) return@forEach
            root.walkTopDown().filter { it.isFile }.forEach { file ->
                val relative = file.relativeTo(root).invariantSeparatorsPath
                val matches = patternMatchers.any { it.matches(relative) }
                val target = outRoot.resolve(relative)
                target.parentFile.mkdirs()
                if (matches) {
                    val sealed = com.androidshield.core.crypto.ResourcePayloadCodec.seal(
                        plain = file.readBytes(),
                        key = key,
                    )
                    target.writeBytes(sealed)
                    logger.info("Encrypted asset {}", relative)
                } else {
                    file.copyTo(target, overwrite = true)
                }
            }
        }
    }

    private fun globToRegex(glob: String): Regex {
        val escaped = glob
            .replace(".", "\\.")
            .replace("**/", "§DOUBLE§")
            .replace("**", "§DOUBLE§")
            .replace("*", "[^/]*")
            .replace("§DOUBLE§", ".*")
        return Regex("^$escaped$")
    }
}

abstract class GenerateSecurityReportTask : DefaultTask() {
    @get:Internal
    abstract val extensionRef: Property<AndroidShieldExtension>

    @get:Input
    abstract val minifyEnabled: Property<Boolean>

    @get:Input
    abstract val debuggable: Property<Boolean>

    @get:Input
    abstract val failOnValidationError: Property<Boolean>

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun writeReport() {
        val ext = extensionRef.get()
        val features = mapOf(
            "antiDebug" to ext.antiDebug.get(),
            "antiTamper" to ext.antiTamper.get(),
            "antiHook" to ext.antiHook.get(),
            "rootDetection" to ext.rootDetection.get(),
            "emulatorDetection" to ext.emulatorDetection.get(),
            "runtimeProtection" to ext.runtimeProtection.get(),
            "playIntegrity" to ext.playIntegrity.get(),
            "stringEncryption" to ext.stringEncryption.get(),
            "resourceEncryption" to ext.resourceEncryption.get(),
            "sslPinning" to ext.sslPinning.get(),
            "nativeProtection" to ext.nativeProtection.get(),
            "bytecodeObfuscation" to ext.bytecodeObfuscation.get(),
        )
        val validation = ReleaseValidator.validate(ext, minifyEnabled.get(), debuggable.get())
        val report = BuildSecurityReporter.create(features, validation)
        reportFile.get().asFile.parentFile.mkdirs()
        reportFile.get().asFile.writeText(BuildSecurityReporter.toJson(report))
        logger.lifecycle(
            "AndroidShield security report: secure={} score={} threats={}",
            report.secure,
            report.score,
            report.threats.size,
        )
        if (failOnValidationError.get() &&
            validation.any { it.severity == Severity.HIGH || it.severity == Severity.CRITICAL }
        ) {
            throw GradleException(
                "AndroidShield release validation failed — see ${reportFile.get().asFile}",
            )
        }
    }
}

abstract class ProtectMappingTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val mappingFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val protectedDir: DirectoryProperty

    @TaskAction
    fun protect() {
        val out = protectedDir.get().asFile
        out.mkdirs()
        mappingFiles.files.filter { it.exists() }.forEach { mapping ->
            val target = out.resolve(mapping.name + ".shielded")
            val bytes = mapping.readBytes()
            val scrambled = bytes.mapIndexed { index, b ->
                (b.toInt() xor (0x5A + index % 17)).toByte()
            }.toByteArray()
            target.writeBytes(scrambled)
            out.resolve(mapping.name + ".access").writeText("restricted")
            logger.lifecycle("Protected mapping {}", mapping.name)
        }
    }
}
