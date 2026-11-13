plugins {
    id("com.android.application")
}

val repoRoot: File = rootProject.projectDir.parentFile
val profiles = listOf(
    "sog02-58.2.C.3.127",
    "so-51a-58.2.B.0.520",
    "so-52a-58.2.B.0.520",
    "sog01-58.2.C.5.10",
)

android {
    namespace = "com.miyoubi.fracture"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.miyoubi.fracture"
        minSdk = 31
        targetSdk = 34
        versionCode = 2
        versionName = "2.0"
        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=none")
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}

/*
 * The exploit and the KernelSU module are streamed into /data/local/tmp by
 * the app through Shizuku, so they live in assets (assets survive packaging
 * unmodified; a .ko under jniLibs would be stripped).
 */
val stageAssets = tasks.register("stageAssets") {
    val out = file("src/main/assets/exploit")
    outputs.dir(out)
    doLast {
        out.mkdirs()
        val unified = File(repoRoot, "build/unified/libfracture.so")
        if (unified.isFile) {
            unified.copyTo(File(out, "libfracture.so"), overwrite = true)
        } else {
            logger.warn("missing ${unified.path}; run make PROJECT=unified")
        }
        var ko: File? = null
        profiles.forEach { p ->
            val k = File(repoRoot, "build/$p/kernelsu.ko")
            if (ko == null && k.isFile) ko = k
        }
        if (ko == null) {
            val unifiedKo = File(repoRoot, "build/unified/kernelsu.ko")
            if (unifiedKo.isFile) ko = unifiedKo
        }
        ko?.copyTo(File(out, "kernelsu.ko"), overwrite = true)
    }
}

tasks.named("preBuild") {
    dependsOn(stageAssets)
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core:1.13.1")
    implementation("com.google.android.material:material:1.13.0")
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
}
