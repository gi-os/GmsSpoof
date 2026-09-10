plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.gios.gmsspoof"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.gios.gmsspoof"
        // Deliberately low — this is a throwaway probe, it must install no matter
        // what the KY-42C's real API level turns out to be. Raise once known.
        minSdk = 21
        targetSdk = 29
        versionCode = 2
        versionName = "1.1.0"
    }

    buildTypes {
        debug {
            isDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = false
    }
}

dependencies {
    compileOnly(files("libs/XposedBridgeAPI-82.jar"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
}
