package com.androidshield.plugin.transform

import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import com.androidshield.plugin.transform.visitors.ShieldClassVisitor
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.objectweb.asm.ClassVisitor

/**
 * Instrumentation parameters serialized into AGP workers.
 */
interface ShieldTransformParams : InstrumentationParameters {
    @get:Input
    val stringEncryption: Property<Boolean>

    @get:Input
    val stripMetadata: Property<Boolean>

    @get:Input
    val deadCodeInsertion: Property<Boolean>

    @get:Input
    val opaquePredicates: Property<Boolean>

    @get:Input
    val controlFlowFlattening: Property<Boolean>

    @get:Input
    val obfuscationIntensity: Property<Int>

    @get:Input
    val scrambledKeyBase64: Property<String>

    @get:Input
    val seedBase64: Property<String>

    @get:Input
    val protectPackages: ListProperty<String>
}

/**
 * AGP ASM class visitor factory for AndroidShield bytecode protection.
 */
abstract class ShieldAsmFactory : AsmClassVisitorFactory<ShieldTransformParams> {
    override fun createClassVisitor(
        classContext: ClassContext,
        nextClassVisitor: ClassVisitor,
    ): ClassVisitor {
        val params = parameters.get()
        return ShieldClassVisitor(
            api = instrumentationContext.apiVersion.get(),
            next = nextClassVisitor,
            className = classContext.currentClassData.className,
            stringEncryption = params.stringEncryption.get(),
            stripMetadata = params.stripMetadata.get(),
            deadCodeInsertion = params.deadCodeInsertion.get(),
            opaquePredicates = params.opaquePredicates.get(),
            controlFlowFlattening = params.controlFlowFlattening.get(),
            intensity = params.obfuscationIntensity.get(),
            scrambledKeyBase64 = params.scrambledKeyBase64.get(),
            seedBase64 = params.seedBase64.get(),
        )
    }

    override fun isInstrumentable(classData: ClassData): Boolean {
        val name = classData.className
        if (name.startsWith("com.androidshield.runtime.crypto")) return false
        if (name.startsWith("android.") || name.startsWith("androidx.")) return false
        if (name.startsWith("kotlin.") || name.startsWith("kotlinx.")) return false
        if (name.startsWith("java.") || name.startsWith("javax.")) return false

        val packages = parameters.get().protectPackages.get()
        if (packages.isEmpty()) return true
        return packages.any { pkg -> name == pkg || name.startsWith("$pkg.") }
    }
}
