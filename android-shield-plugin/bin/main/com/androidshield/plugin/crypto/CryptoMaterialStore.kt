package com.androidshield.plugin.crypto

import org.gradle.api.Project
import java.util.Base64

/**
 * Loads or creates per-project crypto material under the build directory.
 * Stable for a given build tree until `clean`; regenerated after clean.
 */
object CryptoMaterialStore {
    fun obtain(project: Project): BuildCryptoMaterial {
        val file = project.layout.buildDirectory.get().asFile
            .resolve("androidshield/keys/material.txt")
        if (file.exists()) {
            val lines = file.readLines()
            require(lines.size >= 2) { "Corrupt AndroidShield crypto material at $file" }
            val scrambled = Base64.getDecoder().decode(lines[0])
            val seed = Base64.getDecoder().decode(lines[1])
            val key = com.androidshield.core.crypto.KeyScrambler.unscramble(scrambled, seed)
            return BuildCryptoMaterial(key = key, seed = seed, scrambledKey = scrambled)
        }
        val material = BuildCryptoMaterial.generate()
        file.parentFile.mkdirs()
        file.writeText(
            buildString {
                appendLine(Base64.getEncoder().encodeToString(material.scrambledKey))
                appendLine(Base64.getEncoder().encodeToString(material.seed))
            },
        )
        return material
    }
}
