plugins { id("org.jetbrains.kotlin.jvm") }
kotlin {
    jvmToolchain(17)
    sourceSets.getByName("main").kotlin.srcDir("../tools/src")
}
dependencies {
    implementation(project(":gateway-core"))
    implementation(project(":capacity-core"))
    implementation(project(":roaming-core"))
}
tasks.register<JavaExec>("smokeIntegration") {
    group = "verification"
    dependsOn(tasks.named("classes"))
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("IntegratedRoamingSmoke")
}

tasks.register<JavaExec>("smokeQuota") {
    group = "verification"
    dependsOn(tasks.named("classes"))
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("VoucherConcurrencySmoke")
}

tasks.register<JavaExec>("smokePartialQuota") {
    group = "verification"
    dependsOn(tasks.named("classes"))
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("QuotaPartialTcpSmoke")
}

tasks.register<JavaExec>("smokeSessionAdmission") {
    group = "verification"
    dependsOn(tasks.named("classes"))
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("VoucherSessionAdmissionSmoke")
}
