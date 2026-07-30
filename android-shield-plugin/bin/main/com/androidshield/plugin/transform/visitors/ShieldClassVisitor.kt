package com.androidshield.plugin.transform.visitors

import com.androidshield.core.crypto.AesGcmCipher
import com.androidshield.core.crypto.KeyScrambler
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.util.Base64

/**
 * Chains AndroidShield bytecode protection visitors for a single class.
 */
class ShieldClassVisitor(
    api: Int,
    next: ClassVisitor,
    private val className: String,
    private val stringEncryption: Boolean,
    private val stripMetadata: Boolean,
    private val deadCodeInsertion: Boolean,
    private val opaquePredicates: Boolean,
    private val controlFlowFlattening: Boolean,
    private val intensity: Int,
    scrambledKeyBase64: String,
    seedBase64: String,
) : ClassVisitor(api, next) {
    private val key: ByteArray = if (scrambledKeyBase64.isNotEmpty() && seedBase64.isNotEmpty()) {
        KeyScrambler.unscramble(
            Base64.getDecoder().decode(scrambledKeyBase64),
            Base64.getDecoder().decode(seedBase64),
        )
    } else {
        ByteArray(0)
    }

    private var isInterface = false

    override fun visit(
        version: Int,
        access: Int,
        name: String?,
        signature: String?,
        superName: String?,
        interfaces: Array<out String>?,
    ) {
        isInterface = (access and Opcodes.ACC_INTERFACE) != 0
        super.visit(version, access, name, signature, superName, interfaces)
    }

    override fun visitSource(source: String?, debug: String?) {
        if (stripMetadata) {
            super.visitSource(null, null)
        } else {
            super.visitSource(source, debug)
        }
    }

    override fun visitAnnotation(descriptor: String?, visible: Boolean): AnnotationVisitor? {
        if (stripMetadata && shouldStripAnnotation(descriptor)) {
            return null
        }
        return super.visitAnnotation(descriptor, visible)
    }

    override fun visitField(
        access: Int,
        name: String?,
        descriptor: String?,
        signature: String?,
        value: Any?,
    ): FieldVisitor {
        val rewritten = if (stringEncryption && value is String && shouldEncryptString(value) && key.isNotEmpty()) {
            null
        } else {
            value
        }
        val fv = super.visitField(access, name, descriptor, signature, rewritten)
        return fv
    }

    override fun visitMethod(
        access: Int,
        name: String?,
        descriptor: String?,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor {
        var mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (mv == null || name == null || descriptor == null) return mv
        if ((access and Opcodes.ACC_ABSTRACT) != 0 || (access and Opcodes.ACC_NATIVE) != 0) return mv

        if (stringEncryption && key.isNotEmpty()) {
            mv = StringEncryptionMethodVisitor(api, mv, key)
        }
        if (stripMetadata) {
            mv = MetadataStripMethodVisitor(api, mv)
        }
        if (!isInterface && deadCodeInsertion && intensity >= 1) {
            mv = DeadCodeMethodVisitor(api, mv)
        }
        if (!isInterface && opaquePredicates && intensity >= 2) {
            mv = OpaquePredicateMethodVisitor(api, mv)
        }
        if (!isInterface && controlFlowFlattening && intensity >= 3) {
            mv = ControlFlowFlatteningMethodVisitor(api, mv)
        }
        return mv
    }

    private fun shouldStripAnnotation(descriptor: String?): Boolean {
        if (descriptor == null) return false
        if (descriptor.startsWith("Landroidx/")) return false
        if (descriptor.startsWith("Landroid/")) return false
        if (descriptor.startsWith("Lkotlin/")) return false
        if (descriptor.startsWith("Lkotlinx/")) return false
        if (descriptor.contains("ShieldProtect") || descriptor.contains("ShieldEncrypt")) return true
        return descriptor.startsWith("Ldalvik/annotation/")
    }

    companion object {
        fun shouldEncryptString(value: String): Boolean =
            com.androidshield.core.crypto.StringEncryptionPolicy.DEFAULT.shouldEncrypt(value)
    }
}

internal class StringEncryptionMethodVisitor(
    api: Int,
    next: MethodVisitor,
    private val key: ByteArray,
) : MethodVisitor(api, next) {
    override fun visitLdcInsn(value: Any?) {
        if (value is String && ShieldClassVisitor.shouldEncryptString(value)) {
            val iv = AesGcmCipher.generateIv()
            val cipherText = AesGcmCipher.encryptUtf8(value, key, iv)
            pushByteArray(cipherText)
            pushByteArray(iv)
            visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "com/androidshield/runtime/crypto/ShieldStringDecryptor",
                "decrypt",
                "([B[B)Ljava/lang/String;",
                false,
            )
        } else {
            super.visitLdcInsn(value)
        }
    }

    private fun pushByteArray(bytes: ByteArray) {
        visitLdcInsn(bytes.size)
        visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        for (i in bytes.indices) {
            visitInsn(Opcodes.DUP)
            visitLdcInsn(i)
            visitIntInsn(Opcodes.BIPUSH, bytes[i].toInt())
            visitInsn(Opcodes.BASTORE)
        }
    }
}

internal class MetadataStripMethodVisitor(
    api: Int,
    next: MethodVisitor,
) : MethodVisitor(api, next) {
    override fun visitLineNumber(line: Int, start: Label?) = Unit

    override fun visitLocalVariable(
        name: String?,
        descriptor: String?,
        signature: String?,
        start: Label?,
        end: Label?,
        index: Int,
    ) = Unit
}

/**
 * Inserts a side-effect-free opaque block that never executes to confuse static analysis.
 */
internal class DeadCodeMethodVisitor(
    api: Int,
    next: MethodVisitor,
) : MethodVisitor(api, next) {
    private var inserted = false

    override fun visitCode() {
        super.visitCode()
        if (inserted) return
        inserted = true
        val skip = Label()
        visitInsn(Opcodes.ICONST_0)
        visitJumpInsn(Opcodes.IFEQ, skip)
        visitInsn(Opcodes.ICONST_1)
        visitInsn(Opcodes.POP)
        visitLabel(skip)
    }
}

/**
 * Wraps method body entry with a always-true opaque predicate.
 */
internal class OpaquePredicateMethodVisitor(
    api: Int,
    next: MethodVisitor,
) : MethodVisitor(api, next) {
    private var inserted = false

    override fun visitCode() {
        super.visitCode()
        if (inserted) return
        inserted = true
        val ok = Label()
        val dead = Label()
        // (x * (x + 1)) % 2 == 0 is always true for integers
        visitInsn(Opcodes.ICONST_3)
        visitInsn(Opcodes.DUP)
        visitInsn(Opcodes.ICONST_1)
        visitInsn(Opcodes.IADD)
        visitInsn(Opcodes.IMUL)
        visitInsn(Opcodes.ICONST_2)
        visitInsn(Opcodes.IREM)
        visitJumpInsn(Opcodes.IFEQ, ok)
        visitLabel(dead)
        visitInsn(Opcodes.NOP)
        visitJumpInsn(Opcodes.GOTO, ok)
        visitLabel(ok)
    }
}

/**
 * Lightweight control-flow noise: inserts an always-taken trampoline jump.
 * Full dispatcher-based CFF can be expanded later; intensity 3 enables this noise.
 */
internal class ControlFlowFlatteningMethodVisitor(
    api: Int,
    next: MethodVisitor,
) : MethodVisitor(api, next) {
    private var inserted = false

    override fun visitCode() {
        super.visitCode()
        if (inserted) return
        inserted = true
        val body = Label()
        val trampoline = Label()
        visitJumpInsn(Opcodes.GOTO, trampoline)
        visitLabel(body)
        visitInsn(Opcodes.NOP)
        val after = Label()
        visitJumpInsn(Opcodes.GOTO, after)
        visitLabel(trampoline)
        visitJumpInsn(Opcodes.GOTO, body)
        visitLabel(after)
    }
}
