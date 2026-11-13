package com.miyoubi.fracture;

import android.app.Application;

import com.google.android.material.color.DynamicColors;

public final class FractureApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        DynamicColors.applyToActivitiesIfAvailable(
                this,
                new DynamicColorsOptions.Builder()
                        .setPrecondition((activity, theme) ->
                                ThemeHelper.ACCENT_MONET.equals(ThemeHelper.getAccent(activity)))
                        .build());
    }
}
