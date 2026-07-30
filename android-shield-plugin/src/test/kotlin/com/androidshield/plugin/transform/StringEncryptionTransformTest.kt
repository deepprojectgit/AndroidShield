package com.androidshield.plugin.transform

import com.androidshield.core.crypto.AesGcmCipher
import com.androidshield.core.crypto.KeyScrambler
import com.androidshield.plugin.r8.R8RulesGenerator
import com.androidshield.plugin.transform.visitors.ShieldClassVisitor
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import java.util.Base64

class StringEncryptionTransformTest {
    @Test
    fun encryptsHttpLiteral_toDecryptCall() {
        val key = AesGcmCipher.generateKey()
        val seed = KeyScrambler.randomSeed()
        val scrambled = KeyScrambler.scramble(key, seed)

        val original = buildClassWithString("https://secure.example/api/key")
        val reader = ClassReader(original)
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        val visitor = ShieldClassVisitor(
            api = Opcodes.ASM9,
            next = writer,
            className = "com.example.Demo",
            stringEncryption = true,
            stripMetadata = true,
            deadCodeInsertion = false,
            opaquePredicates = false,
            controlFlowFlattening = false,
            intensity = 1,
            scrambledKeyBase64 = Base64.getEncoder().encodeToString(scrambled),
            seedBase64 = Base64.getEncoder().encodeToString(seed),
        )
        reader.accept(visitor, 0)

        val node = ClassNode()
        ClassReader(writer.toByteArray()).accept(node, 0)
        val method = node.methods.first { it.name == "value" }
        val hasDecrypt = method.instructions.toArray().any {
            it is MethodInsnNode &&
                it.owner == "com/androidshield/runtime/crypto/ShieldStringDecryptor" &&
                it.name == "decrypt"
        }
        val hasPlainLdc = method.instructions.toArray().any {
            it is LdcInsnNode && it.cst == "https://secure.example/api/key"
        }
        assertThat(hasDecrypt).isTrue()
        assertThat(hasPlainLdc).isFalse()
    }

    @Test
    fun r8Rules_containRuntimeKeeps() {
        val rules = R8RulesGenerator.generate(listOf("com.example"), mappingProtection = true)
        assertThat(rules).contains("AndroidShield")
        assertThat(rules).contains("com.androidshield.runtime.api.AndroidShield")
        assertThat(rules).contains("-repackageclasses")
    }

    private fun buildClassWithString(literal: String): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/Demo", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()Ljava/lang/String;", null, null)
        mv.visitCode()
        mv.visitLdcInsn(literal)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
}
