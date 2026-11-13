package com.miyoubi.fracture;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.materialswitch.MaterialSwitch;

public final class SettingsActivity extends AppCompatActivity {

    private String appliedAccent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ThemeHelper.apply(this);
        super.onCreate(savedInstanceState);
        appliedAccent = ThemeHelper.getAccent(this);
        setContentView(R.layout.activity_settings);

        MaterialToolbar toolbar = findViewById(R.id.topAppBar);
        setSupportActionBar(toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        SharedPreferences prefs = getSharedPreferences("settings", MODE_PRIVATE);
        MaterialSwitch switchKsu = findViewById(R.id.switchKsu);
        MaterialSwitch switchReboot = findViewById(R.id.switchReboot);
        MaterialSwitch switchOpenManager = findViewById(R.id.switchOpenManager);
        MaterialSwitch switchKeepScreenOn = findViewById(R.id.switchKeepScreenOn);
        MaterialSwitch switchSkipSelinux = findViewById(R.id.switchSkipSelinux);
        MaterialSwitch switchDetailedOutput = findViewById(R.id.switchDetailedOutput);
        MaterialSwitch switchTransparentOutput = findViewById(R.id.switchTransparentOutput);
        AutoCompleteTextView dropdownKsuDisplay = findViewById(R.id.dropdownKsuDisplay);
        MaterialSwitch switchHideShizuku = findViewById(R.id.switchHideShizuku);

        boolean ksu = prefs.getBoolean("ksu", true);
        boolean reboot = prefs.getBoolean("reboot", false);
        switchKsu.setChecked(ksu);
        switchReboot.setChecked(reboot);
        switchReboot.setEnabled(ksu);
        switchOpenManager.setChecked(prefs.getBoolean("open_manager", true));
        switchKeepScreenOn.setChecked(prefs.getBoolean("keep_screen_on", false));
        switchSkipSelinux.setChecked(prefs.getBoolean("skip_selinux_enforce", false));
        if (switchDetailedOutput != null) {
            switchDetailedOutput.setChecked(prefs.getBoolean("detailed_output", false));
        }
        if (switchTransparentOutput != null) {
            switchTransparentOutput.setChecked(prefs.getBoolean("transparent_output", false));
        }
        if (switchHideShizuku != null) {
            switchHideShizuku.setChecked(prefs.getBoolean("hide_shizuku_card", false));
            switchHideShizuku.setOnCheckedChangeListener((button, checked) ->
                    prefs.edit().putBoolean("hide_shizuku_card", checked).apply());
        }

        AutoCompleteTextView dropdownAccentColor = findViewById(R.id.dropdownAccentColor);
        if (dropdownAccentColor != null) {
            String[] accentValues = {
                    ThemeHelper.ACCENT_PURPLE,
                    ThemeHelper.ACCENT_BLUE,
                    ThemeHelper.ACCENT_GREEN,
                    ThemeHelper.ACCENT_RED,
                    ThemeHelper.ACCENT_ORANGE,
                    ThemeHelper.ACCENT_PINK,
                    ThemeHelper.ACCENT_TEAL,
                    ThemeHelper.ACCENT_MONET
            };
            String[] accentLabels = {
                    getString(R.string.accent_purple),
                    getString(R.string.accent_blue),
                    getString(R.string.accent_green),
                    getString(R.string.accent_red),
                    getString(R.string.accent_orange),
                    getString(R.string.accent_pink),
                    getString(R.string.accent_teal),
                    getString(R.string.accent_monet)
            };
            AccentColorAdapter accentAdapter = new AccentColorAdapter(this, accentLabels, accentValues);
            dropdownAccentColor.setAdapter(accentAdapter);
            String accent = ThemeHelper.getAccent(this);
            int accentIndex = 0;
            for (int i = 0; i < accentValues.length; i++) {
                if (accentValues[i].equals(accent)) {
                    accentIndex = i;
                    break;
                }
            }
            dropdownAccentColor.setText(accentLabels[accentIndex], false);
            dropdownAccentColor.setOnItemClickListener((parent, view, position, id) -> {
                String selected = accentAdapter.valueAt(position);
                if (!selected.equals(ThemeHelper.getAccent(this))) {
                    prefs.edit().putString(ThemeHelper.PREF_ACCENT, selected).apply();
                    recreate();
                }
            });
        }

        if (dropdownKsuDisplay != null) {
            String[] labels = {
                    getString(R.string.ksu_display_card),
                    getString(R.string.ksu_display_chip),
                    getString(R.string.ksu_display_button)
            };
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                    android.R.layout.simple_list_item_1, labels);
            dropdownKsuDisplay.setAdapter(adapter);
            String mode = prefs.getString("ksu_active_display", "card");
            int index = 0;
            if ("chip".equals(mode)) index = 1;
            else if ("button".equals(mode)) index = 2;
            dropdownKsuDisplay.setText(labels[index], false);
            dropdownKsuDisplay.setOnItemClickListener((parent, view, position, id) -> {
                String value = "card";
                if (position == 1) value = "chip";
                else if (position == 2) value = "button";
                prefs.edit().putString("ksu_active_display", value).apply();
            });
        }

        switchKsu.setOnCheckedChangeListener((button, checked) -> {
            prefs.edit().putBoolean("ksu", checked).apply();
            switchReboot.setEnabled(checked);
            if (!checked) {
                switchReboot.setChecked(false);
                prefs.edit().putBoolean("reboot", false).apply();
            }
        });
        switchReboot.setOnCheckedChangeListener((button, checked) ->
                prefs.edit().putBoolean("reboot", checked).apply());
        switchOpenManager.setOnCheckedChangeListener((button, checked) ->
                prefs.edit().putBoolean("open_manager", checked).apply());
        switchKeepScreenOn.setOnCheckedChangeListener((button, checked) ->
                prefs.edit().putBoolean("keep_screen_on", checked).apply());
        switchSkipSelinux.setOnCheckedChangeListener((button, checked) ->
                prefs.edit().putBoolean("skip_selinux_enforce", checked).apply());
        if (switchDetailedOutput != null) {
            switchDetailedOutput.setOnCheckedChangeListener((button, checked) ->
                    prefs.edit().putBoolean("detailed_output", checked).apply());
        }
        if (switchTransparentOutput != null) {
            switchTransparentOutput.setOnCheckedChangeListener((button, checked) ->
                    prefs.edit().putBoolean("transparent_output", checked).apply());
        }

        TextView tvProfile = findViewById(R.id.tvProfileValue);
        TextView tvLastRun = findViewById(R.id.tvLastRunValue);
        DeviceProfile device = DeviceProfile.detect(this);
        String profile = device.profile != null ? device.profile : getString(R.string.unsupported);
        tvProfile.setText(profile);

        long lastRun = prefs.getLong("last_run", 0);
        if (lastRun <= 0) {
            tvLastRun.setText(R.string.last_run_none);
        } else {
            boolean rebooted = prefs.getBoolean("last_rebooted", false);
            if (rebooted) {
                tvLastRun.setText(R.string.last_run_reboot);
            } else {
                int code = prefs.getInt("last_exit", -1);
                tvLastRun.setText(getString(R.string.last_run_result, code));
            }
        }

        View sendLogs = findViewById(R.id.cardSendLogs);
        if (sendLogs != null) {
            sendLogs.setOnClickListener(v -> shareLogs(device));
        }
    }

    private void shareLogs(DeviceProfile device) {
        StringBuilder sb = new StringBuilder();
        sb.append("Fracture log\n");
        if (device != null) {
            sb.append("Model: ").append(device.model).append('\n');
            sb.append("Build: ").append(device.build).append('\n');
            sb.append("Android: ").append(device.androidLabel()).append('\n');
            sb.append("Kernel: ").append(device.kernel).append('\n');
            sb.append("Profile: ").append(device.profile != null ? device.profile : "unsupported").append('\n');
        }
        sb.append("\n").append(LogStore.getDetailed());
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, "Fracture log");
        intent.putExtra(Intent.EXTRA_TEXT, sb.toString());
        startActivity(Intent.createChooser(intent, getString(R.string.share_log)));
    }
}
