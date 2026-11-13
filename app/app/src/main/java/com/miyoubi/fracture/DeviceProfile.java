package com.miyoubi.fracture;

import android.content.Context;
import android.os.Build;

import java.io.InputStream;

/** Device identity and whether this build has a working payload for it. */
final class DeviceProfile {

    final String model;
    final String build;
    final String release;
    final String kernel;
    final int sdk;
    final String profile;      // null when the model/build is unknown
    final boolean supported;   // profile known and the exploit asset is bundled

    private DeviceProfile(String model, String build, String release, String kernel,
                          int sdk, String profile, boolean supported) {
        this.model = model;
        this.build = build;
        this.release = release;
        this.kernel = kernel;
        this.sdk = sdk;
        this.profile = profile;
        this.supported = supported;
    }

    static String profileFor(String model, String build) {
        switch (model + "|" + build) {
            case "SOG02|58.2.C.3.127": return "sog02-58.2.C.3.127";
            case "SO-51A|58.2.B.0.520": return "so-51a-58.2.B.0.520";
            case "SO-52A|58.2.B.0.520": return "so-52a-58.2.B.0.520";
            case "SOG01|58.2.C.5.10": return "sog01-58.2.C.5.10";
            case "XQ-AT42|58.2.A.10.102": return "unified";
            case "XQ-AT51|58.2.A.7.93": return "unified";
            case "XQ-AT52|58.2.A.7.93": return "unified";
            case "XQ-AT72|58.2.A.10.44A": return "unified";
            case "XQ-AS42|58.2.A.10.163": return "unified";
            case "XQ-AS52|58.2.A.10.126": return "unified";
            case "XQ-AS62|58.2.A.10.126": return "unified";
            case "XQ-AS72|58.2.A.10.126": return "unified";
            default: break;
        }
        switch (model) {
            case "XQ-AT42":
            case "XQ-AT51":
            case "XQ-AT52":
            case "XQ-AT72":
            case "XQ-AS42":
            case "XQ-AS52":
            case "XQ-AS62":
            case "XQ-AS72":
                return "unified";
            default:
                return null;
        }
    }

    static DeviceProfile detect(Context ctx) {
        String model = Build.MODEL == null ? "?" : Build.MODEL;
        String build = Build.DISPLAY == null ? "?" : Build.DISPLAY;
        String profile = profileFor(model, build);
        boolean present = false;
        if (profile != null) {
            try (InputStream in = ctx.getAssets().open("exploit/libfracture.so")) {
                present = in != null;
            } catch (Exception ignored) {
            }
        }
        return new DeviceProfile(model, build, Build.VERSION.RELEASE,
                System.getProperty("os.version", "?"), Build.VERSION.SDK_INT,
                profile, present);
    }

    String androidLabel() {
        return release + "  (API " + sdk + ")";
    }
}
