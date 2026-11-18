plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "link.dtn.shell"
    compileSdk = 34

    defaultConfig {
        applicationId = "link.dtn.shell"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.20.0"
    }

    testOptions {
        unitTests.isIncludeAndroidResources = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // org.json ships in Android; the JVM unit tests need the artifact.
    testImplementation("org.json:json:20240303")
}
