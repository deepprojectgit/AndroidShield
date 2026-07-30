package com.androidshield.sample.demo

import com.androidshield.annotations.EncryptAlgorithm
import com.androidshield.annotations.ShieldEncrypt
import com.androidshield.annotations.ShieldProtect

/**
 * Demo type showing annotation surface for the Gradle plugin.
 *
 * When `io.github.deepprojectgit.androidshield` is applied with string encryption / package
 * protection enabled, these markers guide ASM transforms. In this monorepo the
 * sample depends on runtime/annotations directly; consumers apply the plugin.
 */
@ShieldProtect(intensity = 2)
object ProtectedSecrets {
    @ShieldEncrypt(algorithm = EncryptAlgorithm.AES_GCM)
    const val DEMO_TOKEN: String = "androidshield-demo-token"

    @ShieldProtect(intensity = 1)
    fun greeting(user: String): String = "Protected hello, $user"
}
