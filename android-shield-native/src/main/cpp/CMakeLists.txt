cmake_minimum_required(VERSION 3.22.1)
project(androidshield LANGUAGES CXX)

# Applied to Debug and Release before targets are created (Play 16 KB pages).
set(CMAKE_SHARED_LINKER_FLAGS
    "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384")

add_library(androidshield SHARED
    android_shield_jni.cpp
    anti_debug.cpp
    anti_hook.cpp
    memory.cpp
    integrity.cpp
    crypto.cpp
)

find_library(log-lib log)

target_compile_features(androidshield PRIVATE cxx_std_17)
target_compile_options(androidshield PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
)

target_link_libraries(androidshield
    ${log-lib}
)

# Google Play / Android 15+: ELF LOAD segments must be 16 KB aligned.
# NDK r27 ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES also sets this; keep explicit for older toolchains.
target_link_options(androidshield PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)
