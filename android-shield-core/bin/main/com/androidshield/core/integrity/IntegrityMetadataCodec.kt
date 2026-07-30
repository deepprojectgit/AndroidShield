package com.androidshield.core.integrity

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Serialize / parse [IntegrityMetadata] for assets and runtime loading.
 */
object IntegrityMetadataCodec {
    private val json = Json {
        prettyPrint = false
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    fun encode(metadata: IntegrityMetadata): String = json.encodeToString(metadata)

    fun encodePretty(metadata: IntegrityMetadata): String =
        Json { prettyPrint = true; encodeDefaults = true; ignoreUnknownKeys = true }
            .encodeToString(metadata)

    fun decode(raw: String): IntegrityMetadata = json.decodeFromString(raw)

    fun decode(bytes: ByteArray): IntegrityMetadata =
        decode(bytes.toString(Charsets.UTF_8))
}
