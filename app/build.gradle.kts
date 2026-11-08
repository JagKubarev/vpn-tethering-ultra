// WebUI модуля VPN Tethering Ultra отдельным приложением (KernelSU / Magisk / APatch).
// Без библиотек: только Android SDK. Сборка: gradle assembleRelease (Gradle 8.7, JDK 17+).
import java.util.Properties

plugins {
    id("com.android.application") version "8.5.2"
}

// Подпись release: keystore.properties рядом (локально) или переменные окружения (Actions).
// Ключ должен быть всегда один — иначе новая версия не встанет поверх старой.
val ks = Properties().apply {
    val f = file("keystore.properties")
    if (f.isFile) f.inputStream().use { load(it) }
    System.getenv("VT_KEYSTORE")?.let { setProperty("storeFile", it) }
    System.getenv("VT_KEYSTORE_PASS")?.let { setProperty("storePassword", it); setProperty("keyPassword", it) }
    System.getenv("VT_KEY_ALIAS")?.let { setProperty("keyAlias", it) }
}
val hasKey = ks.getProperty("storeFile")?.let { file(it).isFile } == true

android {
    namespace = "io.github.jagkubarev.vtwebui"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.github.jagkubarev.vtwebui"
        minSdk = 26          // Android 8.0 (MT6580 — 8.1)
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        if (hasKey) create("release") {
            storeFile = file(ks.getProperty("storeFile"))
            storePassword = ks.getProperty("storePassword")
            keyAlias = ks.getProperty("keyAlias")
            keyPassword = ks.getProperty("keyPassword") ?: ks.getProperty("storePassword")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // без ключа — отладочным, чтобы APK всё равно ставился
            signingConfig = if (hasKey) signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

base.archivesName.set("VPN_Tether_WebUI")
