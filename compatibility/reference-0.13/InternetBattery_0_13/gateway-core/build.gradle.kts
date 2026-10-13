plugins { id("org.jetbrains.kotlin.jvm") }
kotlin { jvmToolchain(17) }

tasks.register<JavaExec>("smokeGateway") {
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.internetbattery.gateway.Socks5GatewaySmoke")
}
tasks.register<JavaExec>("smokeTls") {
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.internetbattery.gateway.Socks5TlsSmoke")
}
