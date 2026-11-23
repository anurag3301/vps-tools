plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.anurag.noti"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.anurag.noti"
        minSdk = 29
        targetSdk = 35
        versionCode = 2
        versionName = "0.2"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    buildTypes {
        getByName("debug") { buildConfigField("boolean", "ALLOW_HTTP", "false") }
        // Only for emulator screenshots against a local relay (cleartext to 10.0.2.2). Never ship this.
        create("demo") {
            initWith(getByName("debug"))
            buildConfigField("boolean", "ALLOW_HTTP", "true")
            applicationIdSuffix = ".demo"
            matchingFallbacks += "debug"
        }
        release {
            buildConfigField("boolean", "ALLOW_HTTP", "false")
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    val bom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(bom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    testImplementation("junit:junit:4.13.2")
}
