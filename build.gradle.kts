// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("base")
    kotlin("jvm") version "1.9.22" apply false
    kotlin("android") version "1.9.22" apply false
    id("com.android.library") version "8.3.2" apply false
}

tasks.named("build") {
    dependsOn(":dP256:build")
    dependsOn(":dP256Android:assembleRelease")
}