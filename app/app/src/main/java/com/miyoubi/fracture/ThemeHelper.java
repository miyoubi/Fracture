package com.miyoubi.fracture;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;

import com.google.android.material.color.DynamicColors;

final class ThemeHelper {
    static final String PREF_ACCENT = "accent_color";
    static final String ACCENT_MONET = "monet";
    static final String ACCENT_PURPLE = "purple";
    static final String ACCENT_BLUE = "blue";
    static final String ACCENT_GREEN = "green";
    static final String ACCENT_RED = "red";
    static final String ACCENT_ORANGE = "orange";
    static final String ACCENT_PINK = "pink";
    static final String ACCENT_TEAL = "teal";

    private ThemeHelper() {}

    static String getAccent(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE);
        String v = prefs.getString(PREF_ACCENT, ACCENT_MONET);
        return v == null ? ACCENT_MONET : v;
    }

    static void apply(Activity activity) {
        String accent = getAccent(activity);
        if (ACCENT_MONET.equals(accent)) {
            DynamicColors.applyToActivityIfAvailable(activity);
            return;
        }
        int overlay = overlayFor(accent);
        if (overlay != 0) {
            activity.getTheme().applyStyle(overlay, true);
        }
    }

    private static int overlayFor(String accent) {
        switch (accent) {
            case ACCENT_PURPLE: return R.style.ThemeOverlay_Fracture_Accent_Purple;
            case ACCENT_BLUE: return R.style.ThemeOverlay_Fracture_Accent_Blue;
            case ACCENT_GREEN: return R.style.ThemeOverlay_Fracture_Accent_Green;
            case ACCENT_RED: return R.style.ThemeOverlay_Fracture_Accent_Red;
            case ACCENT_ORANGE: return R.style.ThemeOverlay_Fracture_Accent_Orange;
            case ACCENT_PINK: return R.style.ThemeOverlay_Fracture_Accent_Pink;
            case ACCENT_TEAL: return R.style.ThemeOverlay_Fracture_Accent_Teal;
            default: return R.style.ThemeOverlay_Fracture_Accent_Purple;
        }
    }
}
