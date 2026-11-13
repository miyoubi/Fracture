package com.miyoubi.fracture;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;

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

    static int accentColor(String accent) {
        switch (accent) {
            case ACCENT_MONET: return 0;
            case ACCENT_BLUE: return Color.parseColor("#1565C0");
            case ACCENT_GREEN: return Color.parseColor("#2E7D32");
            case ACCENT_RED: return Color.parseColor("#C62828");
            case ACCENT_ORANGE: return Color.parseColor("#E65100");
            case ACCENT_PINK: return Color.parseColor("#AD1457");
            case ACCENT_TEAL: return Color.parseColor("#00695C");
            case ACCENT_PURPLE:
            default: return Color.parseColor("#5B4D8A");
        }
    }

    static GradientDrawable makeCircle(int color, int sizePx) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(color);
        d.setSize(sizePx, sizePx);
        return d;
    }

    static GradientDrawable makeMonetCircle(int sizePx) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColors(new int[]{
                Color.parseColor("#4285F4"),
                Color.parseColor("#34A853"),
                Color.parseColor("#FBBC05"),
                Color.parseColor("#EA4335")
        });
        d.setOrientation(GradientDrawable.Orientation.TL_BR);
        d.setSize(sizePx, sizePx);
        return d;
    }

    static String getAccent(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE);
        String v = prefs.getString(PREF_ACCENT, ACCENT_PURPLE);
        return v == null ? ACCENT_PURPLE : v;
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
