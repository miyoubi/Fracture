package com.miyoubi.fracture;

import android.app.Application;

import com.google.android.material.color.DynamicColors;

public final class FractureApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        if (ThemeHelper.ACCENT_MONET.equals(ThemeHelper.getAccent(this))) {
            DynamicColors.applyToActivitiesIfAvailable(this);
        }
    }
}
