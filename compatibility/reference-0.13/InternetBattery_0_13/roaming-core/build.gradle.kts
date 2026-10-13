plugins { id("org.jetbrains.kotlin.jvm") }
kotlin { jvmToolchain(17) }
dependencies {
    implementation(project(":capacity-core"))
    implementation(project(":gateway-core"))
}
