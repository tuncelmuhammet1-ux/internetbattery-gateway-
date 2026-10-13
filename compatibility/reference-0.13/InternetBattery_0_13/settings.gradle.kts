pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "InternetBattery"
include(":app", ":gateway-core")

include(":capacity-core")
include(":integration-tests")

include(":roaming-core")
include(":broker-core")
