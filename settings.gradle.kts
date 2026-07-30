pluginManagement {
    includeBuild("build-logic")
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "AndroidShield"

include(
    ":android-shield-annotations",
    ":android-shield-core",
    ":android-shield-runtime",
    ":android-shield-native",
    ":android-shield-plugin",
    ":android-shield-cli",
    ":android-shield-testing",
    ":sample-app",
    ":benchmark",
)
