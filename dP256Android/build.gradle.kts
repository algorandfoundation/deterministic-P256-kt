plugins {
    id("com.android.library")
    kotlin("android")
}

group = "foundation.algorand"
version = "1.0-SNAPSHOT"

android {
    namespace = "foundation.algorand.deterministicP256"
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("consumer-rules.pro")
    }

    // Reuse the existing JVM module sources so we don't duplicate code.
    sourceSets {
        getByName("main") {
            java.srcDirs("../dP256/src/main/kotlin")
            resources.srcDirs("../dP256/src/main/resources")
        }
        getByName("test") {
            java.srcDirs("../dP256/src/test/kotlin")
            resources.srcDirs("../dP256/src/test/resources")
        }
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
    // Keep dependencies aligned with the JVM module so behavior matches.
    implementation("cash.z.ecc.android:kotlin-bip39:1.0.8")
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    api("org.apache.commons:commons-math3:3.6.1")
    implementation("com.google.guava:guava:31.0.1-jre")
}

// Android unit tests still run on the JVM.
tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
}
