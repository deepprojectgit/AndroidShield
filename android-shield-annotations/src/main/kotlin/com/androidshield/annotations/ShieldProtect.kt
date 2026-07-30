package com.androidshield.annotations

/**
 * Marks a class, method, or field for build-time protection by the AndroidShield Gradle plugin.
 */
@MustBeDocumented
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.FIELD
)
annotation class ShieldProtect(
    /**
     * Logical protection intensity hint for the bytecode pipeline.
     * Values are interpreted by the Gradle plugin; higher means stronger transforms.
     */
    val intensity: Int = 1
)
