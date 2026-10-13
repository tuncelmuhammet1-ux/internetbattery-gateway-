plugins { kotlin("jvm") }
kotlin { jvmToolchain(17) }
dependencies {
    implementation(project(":capacity-core"))
    testImplementation(project(":gateway-core"))
    testImplementation(project(":roaming-core"))
}
tasks.register<JavaExec>("smokeBroker") {
    dependsOn("testClasses")
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.internetbattery.broker.BrokerRoamingSmoke")
}

// Requires the JDK keytool to create fresh short-lived identities and trusts.
// No private keys are stored in the repository or published as build artifacts.
tasks.register<Exec>("smokeMutualTls") {
    workingDir = rootProject.projectDir
    commandLine("bash", "tools/test_mutual_tls.sh")
}
