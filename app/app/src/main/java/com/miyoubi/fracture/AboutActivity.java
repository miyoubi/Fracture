package com.miyoubi.fracture;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;

public final class AboutActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ThemeHelper.apply(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);

        MaterialToolbar toolbar = findViewById(R.id.topAppBar);
        toolbar.setNavigationOnClickListener(v -> finish());

        bindLink(R.id.tvSourceCode, R.string.about_repo);
        bindLink(R.id.tvMadeByExer, R.string.about_made_by_exer);
        bindLink(R.id.tvMadeByRisuntsy, R.string.about_made_by_risuntsy);
        bindLink(R.id.tvOrigin1, R.string.about_origin_risuntsy);
        bindLink(R.id.tvOrigin2, R.string.about_origin_keto0422);

        TextView tvVersion = findViewById(R.id.tvVersion);
        String versionName = "unknown";
        long versionCode = 0;
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            if (info.versionName != null) versionName = info.versionName;
            versionCode = info.getLongVersionCode();
        } catch (Exception ignored) {
        }
        String sha = BuildConfig.GIT_SHA;
        if (sha != null && !sha.isEmpty() && !"unknown".equals(sha)) {
            tvVersion.setText(getString(R.string.about_version_sha, versionName, sha, versionCode));
        } else {
            tvVersion.setText(getString(R.string.about_version, versionName, versionCode));
        }
    }

    private void bindLink(int viewId, int urlResId) {
        View v = findViewById(viewId);
        if (v != null) {
            v.setOnClickListener(view -> openUrl(getString(urlResId)));
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception ignored) {
        }
    }
}
