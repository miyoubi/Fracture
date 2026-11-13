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
    private TextView tvKernelSuAction;
    private ScrollView logScroll;
    private LinearProgressIndicator progress;
    private TextView logView;
    private Chip chipStatus;
    private Chip chipKernelSuActive;
    private MaterialButton btnRun;
    private MaterialButton btnShizuku;
    private View cardShizuku;
    private com.google.android.material.card.MaterialCardView cardOutput;
    private boolean shizukuReady;
    private boolean ksuManager;
    private String ksuManagerPkg;
    private boolean ksuModule;
    private boolean managerLaunched;
    private boolean running;

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
                toolbar.setSubtitle("v" + versionName);
            }
        }
        View menuCard = findViewById(R.id.menuCard);
        if (menuCard != null) menuCard.setOnClickListener(this::showMenu);

        prefs = getSharedPreferences("settings", MODE_PRIVATE);
        tvShizuku = findViewById(R.id.tvShizuku);
        tvKernelSu = findViewById(R.id.tvKernelSu);
        cardKernelSu = findViewById(R.id.cardKernelSu);
        tvKernelSuAction = findViewById(R.id.tvKernelSuAction);
        logScroll = findViewById(R.id.logScroll);
        progress = findViewById(R.id.progress);
        logView = findViewById(R.id.logView);
        chipStatus = findViewById(R.id.chipStatus);
        chipKernelSuActive = findViewById(R.id.chipKernelSuActive);
        btnRun = findViewById(R.id.btnRun);
        btnShizuku = findViewById(R.id.btnShizuku);
        cardShizuku = findViewById(R.id.cardShizuku);
        cardOutput = findViewById(R.id.cardOutput);
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
        if (LogStore.getDetailed().isEmpty()) {
            appendLog(getString(R.string.ready_hint));
        }
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
        checkKernelSu();
        setBusy(false);
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
        for (String pkg : KSU_PKGS) {
            try {
                getPackageManager().getPackageInfo(pkg, 0);
                ksuManagerPkg = pkg;
                break;
            } catch (Exception ignored) {
            }
        }
        ksuManager = ksuManagerPkg != null;

        boolean nativeActive = NativeProbe.safeIsKernelSuActive();
        boolean receipt = hasInstallReceiptForCurrentBoot();
        ksuModule = nativeActive || receipt;
        updateKernelSuUi();

        // If native probe already confirms, no need for shell probing.
        if (nativeActive) {
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
                ksuModule = NativeProbe.safeIsKernelSuActive() || result || hasInstallReceiptForCurrentBoot();
                updateKernelSuUi();
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
            return;
        }
        managerLaunched = false;
        setBusy(true);
        running = true;
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
                        });
                    }
                });
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
    }

    private boolean isDetailedOutput() {
        return prefs != null && prefs.getBoolean("detailed_output", false);
    }

    private void rebuildLogView() {
        if (logView == null) return;
        String text = isDetailedOutput() ? LogStore.getDetailed() : LogStore.getSimple();
        logView.setText(text);
        if (logScroll != null) {
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        }
    }

    private void appendLog(String line) {
        LogStore.append(line);
        if (logView == null) return;
        if (isDetailedOutput()) {
            logView.setText(LogStore.getDetailed());
        } else if (LogStore.isSimpleLine(line)) {
            CharSequence cur = logView.getText();
            if (cur == null || cur.length() == 0) {
                logView.setText(line + "\n");
            } else {
                logView.append(line + "\n");
            }
        }
        if (logScroll != null) {
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        }
    }
}
