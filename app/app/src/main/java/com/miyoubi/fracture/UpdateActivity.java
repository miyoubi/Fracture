package com.miyoubi.fracture;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

public final class UpdateActivity extends AppCompatActivity {

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView tvCurrent;
    private TextView tvLatest;
    private TextView tvStatus;
    private TextView tvReleaseNotes;
    private TextView tvChangelogEmpty;
    private LinearLayout changelogList;
    private ProgressBar progress;
    private MaterialButton btnOpenRelease;
    private String releaseUrl = UpdateChecker.RELEASES_URL;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ThemeHelper.apply(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_update);

        MaterialToolbar toolbar = findViewById(R.id.topAppBar);
        toolbar.setNavigationOnClickListener(v -> finish());
        View btnCheck = findViewById(R.id.btnCheck);
        if (btnCheck != null) btnCheck.setOnClickListener(v -> refresh());

        tvCurrent = findViewById(R.id.tvCurrentVersion);
        tvLatest = findViewById(R.id.tvLatestVersion);
        tvStatus = findViewById(R.id.tvUpdateStatus);
        tvReleaseNotes = findViewById(R.id.tvReleaseNotes);
        tvChangelogEmpty = findViewById(R.id.tvChangelogEmpty);
        changelogList = findViewById(R.id.changelogList);
        progress = findViewById(R.id.progress);
        btnOpenRelease = findViewById(R.id.btnOpenRelease);

        if (btnOpenRelease != null) {
            btnOpenRelease.setOnClickListener(v -> openUrl(releaseUrl));
        }

        refresh();
    }

    private void refresh() {
        if (progress != null) progress.setVisibility(View.VISIBLE);
        if (tvStatus != null) tvStatus.setText(R.string.update_checking);
        if (btnOpenRelease != null) btnOpenRelease.setEnabled(false);
        UpdateChecker.check(getApplicationContext(), result -> ui.post(() -> bind(result)));
    }

    private void bind(UpdateChecker.Result r) {
        if (isFinishing() || isDestroyed()) return;
        if (progress != null) progress.setVisibility(View.GONE);
        if (btnOpenRelease != null) btnOpenRelease.setEnabled(true);

        releaseUrl = r.releaseUrl != null ? r.releaseUrl : UpdateChecker.RELEASES_URL;

        if (tvCurrent != null) {
            String cur = r.currentVersion != null ? r.currentVersion : "0";
            tvCurrent.setText(getString(R.string.update_current_version, cur));
        }
        if (tvLatest != null) {
            String tag = r.latestTag != null ? r.latestTag : getString(R.string.update_unknown);
            String name = r.releaseName != null && !r.releaseName.equals(r.latestTag) ? " (" + r.releaseName + ")" : "";
            tvLatest.setText(getString(R.string.update_latest_version, tag + name));
        }
        if (tvStatus != null) {
            if (r.releaseError && r.latestTag == null) {
                tvStatus.setText(R.string.update_failed);
            } else if (r.updateAvailable) {
                String tag = r.latestTag != null ? r.latestTag : "";
                tvStatus.setText(getString(R.string.update_available_message, tag));
            } else {
                tvStatus.setText(R.string.update_latest);
            }
        }

        if (tvReleaseNotes != null) {
            String body = r.releaseBody;
            if (body != null && !body.trim().isEmpty()) {
                tvReleaseNotes.setVisibility(View.VISIBLE);
                tvReleaseNotes.setText(body.trim());
            } else {
                tvReleaseNotes.setVisibility(View.GONE);
            }
        }

        if (changelogList != null) {
            changelogList.removeAllViews();
            if (r.commits == null || r.commits.isEmpty()) {
                if (tvChangelogEmpty != null) tvChangelogEmpty.setVisibility(View.VISIBLE);
            } else {
                if (tvChangelogEmpty != null) tvChangelogEmpty.setVisibility(View.GONE);
                LayoutInflater inflater = LayoutInflater.from(this);
                for (UpdateChecker.CommitInfo c : r.commits) {
                    View item = inflater.inflate(R.layout.item_commit, changelogList, false);
                    TextView msg = item.findViewById(R.id.tvCommitMsg);
                    TextView meta = item.findViewById(R.id.tvCommitMeta);
                    if (msg != null) msg.setText(c.message != null && !c.message.isEmpty() ? c.message : "(no message)");
                    StringBuilder m = new StringBuilder();
                    if (c.sha != null && !c.sha.isEmpty()) m.append(c.sha);
                    if (c.author != null && !c.author.isEmpty()) {
                        if (m.length() > 0) m.append(" • ");
                        m.append(c.author);
                    }
                    if (c.date != null && !c.date.isEmpty()) {
                        String d = c.date.length() >= 10 ? c.date.substring(0, 10) : c.date;
                        if (m.length() > 0) m.append(" • ");
                        m.append(d);
                    }
                    if (meta != null) meta.setText(m.toString());
                    changelogList.addView(item);
                }
            }
        }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception ignored) {
        }
    }
}
