cmake_minimum_required(VERSION 3.22.1)
project(androidshield LANGUAGES CXX)

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
