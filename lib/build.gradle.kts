plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.kover") version "0.8.3"
}

android {
    namespace = "foundation.algorand.deterministicP256"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        targetSdk = 34
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}   

dependencies {
    // Credentials
    implementation("androidx.credentials:credentials:1.2.2")

    // BIP 39
    implementation("cash.z.ecc.android:kotlin-bip39:1.0.8")

    // Use the Kotlin JUnit 5 integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")

    // Use the JUnit 5 integration.
    testImplementation(libs.junit.jupiter.engine)

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // This dependency is exported to consumers, that is to say found on their compile classpath.
    api(libs.commons.math3)

    // This dependency is used internally, and not exposed to consumers on their own compile classpath.
    implementation(libs.guava)
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
}