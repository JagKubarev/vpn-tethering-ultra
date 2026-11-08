// WebUI модуля VPN Tethering Ultra отдельным приложением (KernelSU / Magisk / APatch).
// Без библиотек: только Android SDK. Сборка: gradle assembleRelease (Gradle 8.7, JDK 17+).
import java.util.Properties

plugins {
    id("com.android.application") version "8.5.2"
}

// Подпись release: keystore.properties рядом (локально) или переменные окружения (Actions).
// Ключ должен быть всегда один — иначе новая версия не встанет поверх старой.
// Пустое значение (в файле или в секрете) = не задано.
fun env(k: String) = System.getenv(k)?.takeIf { it.isNotEmpty() }
val ks = Properties().apply {
    val f = file("keystore.properties")
    if (f.isFile) f.inputStream().use { load(it) }
    env("VT_KEYSTORE")?.let { setProperty("storeFile", it) }
    env("VT_KEYSTORE_PASS")?.let { setProperty("storePassword", it); setProperty("keyPassword", it) }
    env("VT_KEY_ALIAS")?.let { setProperty("keyAlias", it) }
    env("VT_KEY_PASS")?.let { setProperty("keyPassword", it) }   // если у ключа свой пароль
}
fun ksProp(k: String): String? = ks.getProperty(k)?.takeIf { it.isNotEmpty() }   // без trim: пробел может быть частью пароля
val hasKey = ksProp("storeFile")?.let { file(it).isFile } == true && ksProp("storePassword") != null && ksProp("keyAlias") != null
// Ключ задан, но не полностью (нет файла, пароля или alias) — release не собираем:
// иначе тихо вышел бы APK с отладочной подписью, и следующая версия не встала бы поверх.
// Отладочная подпись — только когда ключ не задан совсем.
val keyConfigured = env("VT_KEYSTORE") != null || file("keystore.properties").isFile
val releaseRequested = gradle.startParameter.taskNames.any { it.contains("release", ignoreCase = true) }
if (keyConfigured && !hasKey && releaseRequested)
    throw GradleException("Подпись: ключ задан не полностью (нет файла ключа, пароля или alias) — проверьте keystore.properties или секреты VT_KEYSTORE_*")

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
            storeFile = file(ksProp("storeFile")!!)
            storePassword = ksProp("storePassword")
            keyAlias = ksProp("keyAlias")
            keyPassword = ksProp("keyPassword") ?: ksProp("storePassword")
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
