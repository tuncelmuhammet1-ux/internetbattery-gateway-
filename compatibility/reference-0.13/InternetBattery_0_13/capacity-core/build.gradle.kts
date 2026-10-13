plugins { id("org.jetbrains.kotlin.jvm") }
kotlin { jvmToolchain(17) }

tasks.register<JavaExec>("smokeLedger") {
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.internetbattery.capacity.CapacityLedgerSmoke")
}
tasks.register<JavaExec>("smokeVoucher") {
    group = "verification"
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.internetbattery.capacity.PortableVoucherSmoke")
}
