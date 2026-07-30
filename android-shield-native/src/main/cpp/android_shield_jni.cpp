#include <jni.h>

#include <cstdint>
#include <vector>

#include "anti_debug.h"
#include "anti_hook.h"
#include "crypto.h"
#include "integrity.h"
#include "memory.h"

namespace {

jbyteArray to_jbyte_array(JNIEnv *env, const uint8_t *data, size_t len) {
    jbyteArray arr = env->NewByteArray(static_cast<jsize>(len));
    if (arr == nullptr) {
        return nullptr;
    }
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(len), reinterpret_cast<const jbyte *>(data));
    return arr;
}

bool copy_jbyte_array(JNIEnv *env, jbyteArray arr, std::vector<uint8_t> *out) {
    if (arr == nullptr || out == nullptr) {
        return false;
    }
    const jsize len = env->GetArrayLength(arr);
    out->resize(static_cast<size_t>(len));
    if (len == 0) {
        return true;
    }
    env->GetByteArrayRegion(arr, 0, len, reinterpret_cast<jbyte *>(out->data()));
    return true;
}

}  // namespace

extern "C" {

JNIEXPORT jint JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeSelfCheck(JNIEnv *, jclass) {
    const int debug = androidshield::anti_debug::self_check();
    const int hook = androidshield::anti_hook::self_check();
    const int mem = androidshield::memory::self_check();
    return (debug & 0xff) | ((hook & 0xff) << 8) | ((mem & 0xff) << 16);
}

JNIEXPORT jint JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeCheckDebugger(JNIEnv *, jclass) {
    return androidshield::anti_debug::self_check();
}

JNIEXPORT jint JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeCheckHooks(JNIEnv *, jclass) {
    return androidshield::anti_hook::self_check();
}

JNIEXPORT jint JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeCheckMemory(JNIEnv *, jclass) {
    return androidshield::memory::self_check();
}

JNIEXPORT jlong JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeChecksum(
        JNIEnv *env,
        jclass,
        jbyteArray payload) {
    std::vector<uint8_t> bytes;
    if (!copy_jbyte_array(env, payload, &bytes)) {
        return 0;
    }
    return static_cast<jlong>(androidshield::integrity::checksum(bytes.data(), bytes.size()));
}

JNIEXPORT jbyteArray JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeSha256(
        JNIEnv *env,
        jclass,
        jbyteArray payload) {
    std::vector<uint8_t> bytes;
    if (!copy_jbyte_array(env, payload, &bytes)) {
        return nullptr;
    }
    uint8_t digest[32];
    if (!androidshield::integrity::sha256(bytes.data(), bytes.size(), digest)) {
        return nullptr;
    }
    return to_jbyte_array(env, digest, 32);
}

JNIEXPORT jbyteArray JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeUnscrambleKey(
        JNIEnv *env,
        jclass,
        jbyteArray scrambled,
        jbyteArray seed) {
    std::vector<uint8_t> s;
    std::vector<uint8_t> seedBytes;
    if (!copy_jbyte_array(env, scrambled, &s) || !copy_jbyte_array(env, seed, &seedBytes)) {
        return nullptr;
    }
    std::vector<uint8_t> out;
    if (!androidshield::crypto::unscramble_key(
            s.data(), s.size(), seedBytes.data(), seedBytes.size(), &out)) {
        return nullptr;
    }
    return to_jbyte_array(env, out.data(), out.size());
}

JNIEXPORT jbyteArray JNICALL
Java_com_androidshield_nativebridge_NativeShield_nativeDecryptAesGcm(
        JNIEnv *env,
        jclass,
        jbyteArray cipherText,
        jbyteArray iv,
        jbyteArray key) {
    jclass cipherClass = env->FindClass("com/androidshield/core/crypto/AesGcmCipher");
    if (cipherClass == nullptr) {
        return nullptr;
    }
    // decrypt(cipherText, key, iv)
    jmethodID decrypt = env->GetStaticMethodID(cipherClass, "decrypt", "([B[B[B)[B");
    if (decrypt == nullptr) {
        return nullptr;
    }
    return static_cast<jbyteArray>(
            env->CallStaticObjectMethod(cipherClass, decrypt, cipherText, key, iv));
}

}  // extern "C"
