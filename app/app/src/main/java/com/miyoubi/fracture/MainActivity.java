package com.miyoubi.fracture;

import android.content.Intent;
import android.net.Uri;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.text.method.LinkMovementMethod;
import android.view.LayoutInflater;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.PopupWindow;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.Chip;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import rikka.shizuku.Shizuku;

public final class MainActivity extends AppCompatActivity {

    private static final int SHIZUKU_REQ = 1001;
    private static final String SHIZUKU_PKG = "moe.shizuku.privileged.api";
    private static final String[] KSU_PKGS = {
            "me.weishu.kernelsu",
            "com.rifsxd.ksunext",
            "me.weishu.kernelsu.next",
            "com.sukisu.ultra",
    };

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private final Shizuku.OnRequestPermissionResultListener permissionListener =
            (requestCode, grantResult) -> {
                if (requestCode == SHIZUKU_REQ) ui.post(this::updateShizuku);
            };

    private DeviceProfile device;
    private SharedPreferences prefs;
    private TextView tvShizuku;
    private TextView tvKernelSu;
    private View cardKernelSu;
    private TextView tvKernelSuDetail;
    private TextView tvKernelSuAction;
    private ScrollView logScroll;
    private LinearProgressIndicator progress;
    private TextView logView;
    private TextView logEmpty;
    private Chip chipStatus;
    private Chip chipKernelSuActive;
    private MaterialButton btnRun;
    private MaterialButton btnShizuku;
    private View cardShizuku;
    private com.google.android.material.card.MaterialCardView cardOutput;
    private com.google.android.material.checkbox.MaterialCheckBox cbAutoScroll;
    private com.google.android.material.checkbox.MaterialCheckBox cbTimestamps;
    private boolean shizukuReady;
    private boolean ksuManager;
    private String ksuManagerPkg;
    private String ksuManagerVersion;
    private boolean ksuModule;
    private boolean ksuNativeActive;
    private boolean ksuShellActive;
    private boolean ksuReceipt;
    private boolean managerLaunched;
    private boolean running;
    private boolean autoScroll = true;
    private boolean showTimestamps = false;
    private String selinuxMode;

    private String appliedAccent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ThemeHelper.apply(this);
        super.onCreate(savedInstanceState);
        appliedAccent = ThemeHelper.getAccent(this);
        setContentView(R.layout.activity_main);

        MaterialToolbar toolbar = findViewById(R.id.topAppBar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayShowTitleEnabled(true);
            String versionName = null;
            try {
                PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
                versionName = info.versionName;
            } catch (Exception ignored) {
            }
            if (versionName != null && !versionName.isEmpty()) {
                String sha = BuildConfig.GIT_SHA;
                if (sha != null && !sha.isEmpty() && !"unknown".equals(sha)) {
                    toolbar.setSubtitle("v" + versionName + " (" + sha + ")");
                } else {
                    toolbar.setSubtitle("v" + versionName);
                }
            }
        }
        View menuCard = findViewById(R.id.menuCard);
        if (menuCard != null) menuCard.setOnClickListener(this::showMenu);

        prefs = getSharedPreferences("settings", MODE_PRIVATE);
        tvShizuku = findViewById(R.id.tvShizuku);
        tvKernelSu = findViewById(R.id.tvKernelSu);
        cardKernelSu = findViewById(R.id.cardKernelSu);
        tvKernelSuDetail = findViewById(R.id.tvKernelSuDetail);
        tvKernelSuAction = findViewById(R.id.tvKernelSuAction);
        logScroll = findViewById(R.id.logScroll);
        progress = findViewById(R.id.progress);
        logView = findViewById(R.id.logView);
        logEmpty = findViewById(R.id.logEmpty);
        chipStatus = findViewById(R.id.chipStatus);
        chipKernelSuActive = findViewById(R.id.chipKernelSuActive);
        btnRun = findViewById(R.id.btnRun);
        btnShizuku = findViewById(R.id.btnShizuku);
        cardShizuku = findViewById(R.id.cardShizuku);
        cardOutput = findViewById(R.id.cardOutput);
        cbAutoScroll = findViewById(R.id.cbAutoScroll);
        cbTimestamps = findViewById(R.id.cbTimestamps);
        autoScroll = prefs.getBoolean("output_auto_scroll", true);
        showTimestamps = prefs.getBoolean("output_timestamps", false);
        if (cbAutoScroll != null) {
            cbAutoScroll.setChecked(autoScroll);
            cbAutoScroll.setOnCheckedChangeListener((b, c) -> {
                autoScroll = c;
                prefs.edit().putBoolean("output_auto_scroll", c).apply();
                if (autoScroll) scrollLogToBottom();
            });
        }
        if (cbTimestamps != null) {
            cbTimestamps.setChecked(showTimestamps);
            cbTimestamps.setOnCheckedChangeListener((b, c) -> {
                showTimestamps = c;
                prefs.edit().putBoolean("output_timestamps", c).apply();
                rebuildLogView();
            });
        }
        applyPersonalization();

        View.OnClickListener ksuActiveClick = v -> {
            if (!ksuModule) return;
            if (ksuManager) {
                openKernelSuManager();
            } else {
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW,
                            Uri.parse(getString(R.string.ksu_manager_releases))));
                } catch (Exception ignored) {
                }
            }
        };
        if (cardKernelSu != null) cardKernelSu.setOnClickListener(ksuActiveClick);
        if (chipKernelSuActive != null) chipKernelSuActive.setOnClickListener(ksuActiveClick);

        device = DeviceProfile.detect(this);
        bindDevice();

        btnShizuku.setOnClickListener(v -> shizukuAction());
        btnRun.setOnClickListener(v -> runExploit());

        Shizuku.addRequestPermissionResultListener(permissionListener);
        rebuildLogView();
        updateShizuku();
    }

    @Override
    protected void onResume() {
        super.onResume();
        String currentAccent = ThemeHelper.getAccent(this);
        if (appliedAccent != null && !appliedAccent.equals(currentAccent)) {
            recreate();
            return;
        }
        applyPersonalization();
        rebuildLogView();
        updateShizuku();
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(permissionListener);
        running = false;
        io.shutdownNow();
        super.onDestroy();
    }

    private void showMenu(View anchor) {
        View content = LayoutInflater.from(this).inflate(R.layout.popup_menu, null, false);
        final PopupWindow popup = new PopupWindow(content,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                true);
        popup.setElevation(16f);
        popup.setOutsideTouchable(true);

        View settings = content.findViewById(R.id.action_settings);
        View about = content.findViewById(R.id.action_about);
        View github = content.findViewById(R.id.action_github);
        if (settings != null) {
            settings.setOnClickListener(v -> {
                popup.dismiss();
                startActivity(new Intent(this, SettingsActivity.class));
            });
        }
        if (about != null) {
            about.setOnClickListener(v -> {
                popup.dismiss();
                startActivity(new Intent(this, AboutActivity.class));
            });
        }
        if (github != null) {
            github.setOnClickListener(v -> {
                popup.dismiss();
                openGithubPage();
            });
        }

        content.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
        int xoff = -(content.getMeasuredWidth() - anchor.getWidth());
        popup.showAsDropDown(anchor, xoff, 8, Gravity.END);
    }

    private void openGithubPage() {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW,
                    Uri.parse(getString(R.string.about_repo)));
            startActivity(intent);
        } catch (Exception ignored) {
        }
    }

    private void bindDevice() {
        setRow(R.id.rowModel, R.string.model, device.model);
        setRow(R.id.rowBuild, R.string.build, device.build);
        setRow(R.id.rowAndroid, R.string.android, device.androidLabel());
        setRow(R.id.rowKernel, R.string.kernel, device.kernel);

        boolean ok = device.supported;
        chipStatus.setText(ok ? R.string.supported : R.string.unsupported);
        int bg = android.graphics.Color.parseColor(ok ? "#1E3A2F" : "#3A2226");
        int fg = android.graphics.Color.parseColor(ok ? "#8FE0B0" : "#FFB4AB");
        chipStatus.setChipBackgroundColor(ColorStateList.valueOf(bg));
        chipStatus.setTextColor(fg);
        chipStatus.setChipIconVisible(false);
        chipStatus.setCheckedIconVisible(false);
        updatePreRunChecks();
    }

    private void setRow(int rowId, int labelId, String value) {
        View row = findViewById(rowId);
        if (row == null) return;
        ((TextView) row.findViewById(R.id.label)).setText(labelId);
        ((TextView) row.findViewById(R.id.value)).setText(value);
    }

    private void shizukuAction() {
        try {
            if (!Shizuku.pingBinder()) {
                openShizuku();
                return;
            }
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(SHIZUKU_REQ);
                return;
            }
        } catch (Throwable ignored) {
            openShizuku();
            return;
        }
        updateShizuku();
    }

    private void openShizuku() {
        try {
            Intent intent = getPackageManager().getLaunchIntentForPackage(SHIZUKU_PKG);
            if (intent != null) startActivity(intent);
        } catch (Exception ignored) {
        }
    }

    private void updateShizuku() {
        boolean running = false;
        boolean granted = false;
        try {
            running = Shizuku.pingBinder();
            granted = running
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable ignored) {
        }
        shizukuReady = running && granted;
        if (!running) {
            tvShizuku.setText(R.string.shizuku_not_running);
            btnShizuku.setText(R.string.open_shizuku);
        } else if (!granted) {
            tvShizuku.setText(R.string.shizuku_permission);
            btnShizuku.setText(R.string.grant);
        } else {
            tvShizuku.setText(R.string.shizuku_ready);
            btnShizuku.setText(R.string.refresh);
        }
        updatePreRunChecks();
        checkKernelSu();
        setBusy(false);
    }


    private boolean hasAsset(String name) {
        try (java.io.InputStream in = getAssets().open(name)) {
            return in != null;
        } catch (Exception ignored) {
            return false;
        }
    }

    private String readSelinuxMode() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/sys/fs/selinux/enforce"))) {
            String line = reader.readLine();
            if (line == null) return null;
            line = line.trim();
            if ("1".equals(line)) return getString(R.string.selinux_enforcing);
            if ("0".equals(line)) return getString(R.string.selinux_permissive);
        } catch (Throwable ignored) {
        }
        try {
            java.lang.Process p = new java.lang.ProcessBuilder("getenforce")
                    .redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line = r.readLine();
                p.waitFor();
                if (line != null) {
                    String v = line.trim();
                    if ("Enforcing".equalsIgnoreCase(v)) return getString(R.string.selinux_enforcing);
                    if ("Permissive".equalsIgnoreCase(v)) return getString(R.string.selinux_permissive);
                    if ("Disabled".equalsIgnoreCase(v)) return getString(R.string.selinux_disabled);
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private void updatePreRunChecks() {
        selinuxMode = readSelinuxMode();
        String sel = selinuxMode != null ? selinuxMode : getString(R.string.selinux_unknown);
        setRow(R.id.rowSelinux, R.string.selinux, sel);

        String shizukuInfo = shizukuReady
                ? getString(R.string.shizuku_uid_value, 2000)
                : getString(R.string.shizuku_not_running);
        setRow(R.id.rowShizukuUid, R.string.shizuku_uid, shizukuInfo);

        boolean exploitAsset = hasAsset("exploit/libfracture.so");
        boolean moduleAsset = hasAsset("exploit/kernelsu.ko");
        boolean ksuEnabled = prefs == null || prefs.getBoolean("ksu", true);
        String payload;
        boolean payloadOk = false;
        if (device == null || device.profile == null) {
            payload = getString(R.string.payload_missing_profile);
        } else if (!exploitAsset) {
            payload = getString(R.string.payload_missing_exploit);
        } else if (ksuEnabled && !moduleAsset) {
            payload = getString(R.string.payload_missing_module);
        } else {
            payload = getString(R.string.payload_ready, device.profile);
            payloadOk = true;
        }
        setRow(R.id.rowPayload, R.string.payload, payload);

        int readyRes;
        if (ksuModule) {
            readyRes = R.string.ready_ksu_live;
        } else if (running) {
            readyRes = R.string.ready_running;
        } else if (!payloadOk || (device != null && !device.supported)) {
            readyRes = (device == null || device.profile == null) ? R.string.ready_unsupported : R.string.ready_no_payload;
            if (device != null && !device.supported) readyRes = R.string.ready_unsupported;
        } else if (!shizukuReady) {
            readyRes = R.string.ready_need_shizuku;
        } else {
            readyRes = R.string.ready_ok;
        }
        setRow(R.id.rowReady, R.string.ready_status, getString(readyRes));
    }

    private void checkKernelSu() {
        checkKernelSu(false);
    }

    private String currentBootId() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/sys/kernel/random/boot_id"))) {
            String line = reader.readLine();
            return line == null ? null : line.trim();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private boolean hasInstallReceiptForCurrentBoot() {
        String bootId = currentBootId();
        if (bootId == null || bootId.isEmpty() || prefs == null) return false;
        return prefs.getBoolean("ksu_verified", false)
                && bootId.equals(prefs.getString("ksu_verified_boot_id", null));
    }

    private void storeInstallReceiptForCurrentBoot() {
        String bootId = currentBootId();
        if (bootId == null || bootId.isEmpty() || prefs == null) return;
        prefs.edit()
                .putBoolean("ksu_verified", true)
                .putString("ksu_verified_boot_id", bootId)
                .apply();
    }

    private void checkKernelSu(boolean openManagerIfLive) {
        ksuManagerPkg = null;
        ksuManagerVersion = null;
        for (String pkg : KSU_PKGS) {
            try {
                android.content.pm.PackageInfo pi = getPackageManager().getPackageInfo(pkg, 0);
                ksuManagerPkg = pkg;
                ksuManagerVersion = pi.versionName;
                break;
            } catch (Exception ignored) {
            }
        }
        ksuManager = ksuManagerPkg != null;

        ksuNativeActive = NativeProbe.safeIsKernelSuActive();
        ksuReceipt = hasInstallReceiptForCurrentBoot();
        ksuShellActive = false;
        ksuModule = ksuNativeActive || ksuReceipt;
        updateKernelSuUi();
        updatePreRunChecks();

        // If native probe already confirms, no need for shell probing.
        if (ksuNativeActive) {
            if (openManagerIfLive) maybeOpenManager();
            return;
        }

        if (!shizukuReady) return;
        io.submit(() -> {
            final boolean[] live = {false};
            try {
                // /proc/modules is not readable from the app or shell domain
                // here; the KSU su is the reliable loaded-module check.
                ShizukuRunner.exec("su -c id",
                        line -> { if (line.contains("uid=0")) live[0] = true; });
            } catch (Throwable ignored) {
            }
            final boolean result = live[0];
            ui.post(() -> {
                if (result) {
                    storeInstallReceiptForCurrentBoot();
                }
                ksuNativeActive = NativeProbe.safeIsKernelSuActive();
                ksuShellActive = result;
                ksuReceipt = hasInstallReceiptForCurrentBoot();
                ksuModule = ksuNativeActive || ksuShellActive || ksuReceipt;
                updateKernelSuUi();
                updatePreRunChecks();
                if (openManagerIfLive && ksuModule) {
                    maybeOpenManager();
                }
            });
        });
    }

    private String ksuActiveDisplayMode() {
        if (prefs == null) return "card";
        String mode = prefs.getString("ksu_active_display", "card");
        if ("chip".equals(mode) || "button".equals(mode)) return mode;
        return "card";
    }

    private void applyPersonalization() {
        if (cardShizuku != null && prefs != null) {
            boolean hide = prefs.getBoolean("hide_shizuku_card", false);
            cardShizuku.setVisibility(hide ? View.GONE : View.VISIBLE);
        }
        if (cardOutput != null && prefs != null) {
            boolean transparent = prefs.getBoolean("transparent_output", false);
            if (transparent) {
                cardOutput.setCardBackgroundColor(android.graphics.Color.TRANSPARENT);
                cardOutput.setStrokeWidth(0);
            } else {
                cardOutput.setCardBackgroundColor(MaterialColors.getColor(cardOutput,
                        com.google.android.material.R.attr.colorSurfaceContainerHigh));
            }
        }
    }

    private void animateInIfNeeded(View v) {
        if (v == null) return;
        if (v.getVisibility() != View.VISIBLE) {
            v.setAlpha(0f);
            v.setTranslationY(24f);
            v.setVisibility(View.VISIBLE);
            v.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setDuration(350)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator())
                    .start();
        }
    }

    private void updateKernelSuUi() {
        String mode = ksuActiveDisplayMode();
        boolean showCard = ksuModule && "card".equals(mode);
        boolean showChip = ksuModule && "chip".equals(mode);
        boolean showButton = ksuModule && "button".equals(mode);

        int activeBg = MaterialColors.getColor(findViewById(android.R.id.content),
                com.google.android.material.R.attr.colorPrimaryContainer);
        int activeFg = MaterialColors.getColor(findViewById(android.R.id.content),
                com.google.android.material.R.attr.colorOnPrimaryContainer);
        // Orange, translucent (bubble less solid)
        int warnCardBg = android.graphics.Color.parseColor("#26F57C00");
        int warnBubbleBg = android.graphics.Color.parseColor("#40FF9800");
        int warnFg = android.graphics.Color.parseColor("#BF360C");

        int cardBg = ksuManager ? activeBg : warnCardBg;
        int bubbleBg = ksuManager ? activeBg : warnBubbleBg;
        int fg = ksuManager ? activeFg : warnFg;

        if (cardKernelSu != null) {
            if (showCard) {
                animateInIfNeeded(cardKernelSu);
                cardKernelSu.setClickable(true);
                cardKernelSu.setFocusable(true);
                if (cardKernelSu instanceof com.google.android.material.card.MaterialCardView) {
                    ((com.google.android.material.card.MaterialCardView) cardKernelSu)
                            .setCardBackgroundColor(ColorStateList.valueOf(cardBg));
                }
                TextView title = cardKernelSu.findViewById(R.id.tvKernelSuTitle);
                if (title != null) title.setTextColor(fg);
                if (tvKernelSuDetail != null) {
                    String detail = buildKsuDetail();
                    if (detail == null || detail.isEmpty()) {
                        tvKernelSuDetail.setVisibility(View.GONE);
                    } else {
                        tvKernelSuDetail.setText(detail);
                        tvKernelSuDetail.setTextColor(fg);
                        tvKernelSuDetail.setVisibility(View.VISIBLE);
                    }
                }
                if (tvKernelSuAction != null) {
                    tvKernelSuAction.setVisibility(ksuManager ? View.GONE : View.VISIBLE);
                    tvKernelSuAction.setTextColor(fg);
                }
            } else {
                cardKernelSu.setVisibility(View.GONE);
            }
        }

        if (chipKernelSuActive != null) {
            if (showChip) {
                animateInIfNeeded(chipKernelSuActive);
                chipKernelSuActive.setText(R.string.ksu_active_card);
                chipKernelSuActive.setChipBackgroundColor(ColorStateList.valueOf(bubbleBg));
                chipKernelSuActive.setTextColor(fg);
            } else {
                chipKernelSuActive.setVisibility(View.GONE);
            }
        }

        if (btnRun != null) {
            btnRun.setVisibility(View.VISIBLE);
            if (showButton) {
                btnRun.setText(R.string.ksu_active_card);
                btnRun.setEnabled(true);
                btnRun.setAlpha(1f);
                btnRun.setBackgroundTintList(ColorStateList.valueOf(bubbleBg));
                btnRun.setTextColor(fg);
                btnRun.setOnClickListener(v -> {
                    if (ksuManager) openKernelSuManager();
                    else {
                        try {
                            startActivity(new Intent(Intent.ACTION_VIEW,
                                    Uri.parse(getString(R.string.ksu_manager_releases))));
                        } catch (Exception ignored) {
                        }
                    }
                });
            } else {
                if (getString(R.string.ksu_active_card).contentEquals(btnRun.getText())) {
                    btnRun.setText(R.string.run);
                    btnRun.setBackgroundTintList(null);
                    btnRun.setTextColor(MaterialColors.getColor(btnRun,
                            com.google.android.material.R.attr.colorOnPrimary));
                }
                btnRun.setAlpha(1f);
                btnRun.setOnClickListener(v -> runExploit());
            }
        }

        if (ksuModule) {
            tvKernelSu.setVisibility(View.GONE);
            if (!showButton) setBusy(running);
            return;
        }

        if (ksuManager) {
            tvKernelSu.setVisibility(View.GONE);
        } else {
            tvKernelSu.setVisibility(View.VISIBLE);
            tvKernelSu.setText(R.string.ksu_missing);
            tvKernelSu.setTextColor(MaterialColors.getColor(tvKernelSu, androidx.appcompat.R.attr.colorError));
        }
        setBusy(running);
    }

    private void openKernelSuManager() {
        if (!ksuManager || ksuManagerPkg == null) return;
        try {
            PackageManager pm = getPackageManager();
            Intent intent = pm.getLaunchIntentForPackage(ksuManagerPkg);
            if (intent == null) {
                intent = new Intent(Intent.ACTION_MAIN);
                intent.addCategory(Intent.CATEGORY_LAUNCHER);
                intent.setPackage(ksuManagerPkg);
                android.content.pm.ResolveInfo ri = pm.resolveActivity(intent, 0);
                if (ri != null && ri.activityInfo != null) {
                    intent.setClassName(ksuManagerPkg, ri.activityInfo.name);
                } else {
                    intent = null;
                }
            }
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
            } else {
                Toast.makeText(MainActivity.this,
                        "KernelSU manager not found", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            Toast.makeText(MainActivity.this,
                    "Could not open KernelSU manager", Toast.LENGTH_SHORT).show();
        }
    }

    private void maybeOpenManager() {
        if (managerLaunched || !ksuManager || !ksuModule || ksuManagerPkg == null) return;
        if (!prefs.getBoolean("open_manager", true)) return;
        managerLaunched = true;
        final String pkg = ksuManagerPkg;
        io.submit(() -> {
            try {
                StringBuilder pid = new StringBuilder();
                ShizukuRunner.exec("su -c 'pidof " + pkg + "'",
                        line -> pid.append(line).append('\n'));
                if (pid.toString().trim().length() > 0) {
                    // The manager is already up: kill it so it picks up the
                    // freshly loaded module, give the framework a moment.
                    ShizukuRunner.exec("su -c 'am force-stop " + pkg + "'", null);
                    Thread.sleep(3000);
                }
            } catch (Throwable ignored) {
            }
            ui.post(this::openKernelSuManager);
        });
    }

    private void runExploit() {
        if (device == null || !device.supported || !shizukuReady) return;
        if (ksuModule) {
            appendLog("KernelSU is already live; not running the exploit again");
            updatePreRunChecks();
            return;
        }
        managerLaunched = false;
        running = true;
        setBusy(true);
        appendLog("— run —");
        boolean injectKsu = prefs.getBoolean("ksu", true);
        boolean softReboot = prefs.getBoolean("reboot", false);
        boolean skipSelinuxEnforce = prefs.getBoolean("skip_selinux_enforce", false);
        ExploitRunner.run(this, device, injectKsu, ksuModule,
                softReboot, skipSelinuxEnforce,
                new ExploitRunner.Listener() {
                    @Override
                    public void line(String line) {
                        ui.post(() -> appendLog(line));
                    }

                    @Override
                    public void done(int code, boolean softRebooted) {
                        ui.post(() -> {
                            running = false;
                            prefs.edit()
                                    .putLong("last_run", System.currentTimeMillis())
                                    .putInt("last_exit", code)
                                    .putBoolean("last_rebooted", softRebooted)
                                    .apply();
                            if (code == 0 && injectKsu) {
                                storeInstallReceiptForCurrentBoot();
                            }
                            appendLog(softRebooted
                                    ? "— soft reboot requested —"
                                    : "— exit " + code + " —");
                            setBusy(false);
                            checkKernelSu(true);
                            updatePreRunChecks();
                        });
                    }
                });
    }


    private String buildKsuDetail() {
        if (!ksuModule) return null;
        StringBuilder via = new StringBuilder();
        if (ksuNativeActive) via.append(getString(R.string.ksu_detail_native));
        if (ksuShellActive) via.append(getString(R.string.ksu_detail_shell));
        if (ksuReceipt) via.append(getString(R.string.ksu_detail_receipt));
        String mgr;
        if (ksuManager) {
            String ver = (ksuManagerVersion != null && !ksuManagerVersion.isEmpty())
                    ? getString(R.string.ksu_manager_version, ksuManagerVersion) : "";
            mgr = getString(R.string.ksu_manager_detail, ksuManagerPkg, ver);
        } else {
            mgr = getString(R.string.ksu_manager_missing_short);
        }
        return getString(R.string.ksu_active_detail, via.toString(), " • " + mgr);
    }

    private void setBusy(boolean busy) {
        boolean supported = device != null && device.supported;
        boolean buttonModeActive = ksuModule && "button".equals(ksuActiveDisplayMode());
        if (btnRun != null) {
            btnRun.setVisibility(View.VISIBLE);
            if (buttonModeActive) {
                btnRun.setEnabled(true);
                btnRun.setText(R.string.ksu_active_card);
            } else {
                btnRun.setEnabled(!busy && supported && shizukuReady && !ksuModule);
            }
        }
        if (btnShizuku != null) btnShizuku.setEnabled(!busy);
        if (progress != null) progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        if (busy && prefs != null && prefs.getBoolean("keep_screen_on", false)) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        } else {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
        updatePreRunChecks();
    }

    private boolean isDetailedOutput() {
        return prefs != null && prefs.getBoolean("detailed_output", false);
    }

    private void scrollLogToBottom() {
        if (!autoScroll || logScroll == null) return;
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    private void updateLogEmptyState(String text) {
        if (logEmpty == null) return;
        boolean empty = text == null || text.trim().isEmpty();
        logEmpty.setVisibility(empty ? View.VISIBLE : View.GONE);
    }

    private String currentLogText() {
        return isDetailedOutput()
                ? LogStore.getDetailed(showTimestamps)
                : LogStore.getSimple(showTimestamps);
    }

    private void rebuildLogView() {
        if (logView == null) return;
        String text = currentLogText();
        logView.setText(text);
        updateLogEmptyState(text);
        scrollLogToBottom();
    }

    private void appendLog(String line) {
        LogStore.append(line);
        if (logView == null) return;
        String display = showTimestamps
                ? "[" + new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(new java.util.Date()) + "] " + line
                : line;
        if (isDetailedOutput()) {
            String text = currentLogText();
            logView.setText(text);
            updateLogEmptyState(text);
        } else if (LogStore.isSimpleLine(line)) {
            CharSequence cur = logView.getText();
            String newText;
            if (cur == null || cur.length() == 0) {
                newText = display + "\n";
            } else {
                newText = cur.toString() + display + "\n";
            }
            logView.setText(newText);
            updateLogEmptyState(newText);
        } else {
            updateLogEmptyState(logView.getText().toString());
        }
        scrollLogToBottom();
    }
}
