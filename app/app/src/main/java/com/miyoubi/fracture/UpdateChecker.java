package com.miyoubi.fracture;

import android.content.Context;
import android.content.pm.PackageInfo;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class UpdateChecker {
    interface Callback {
        void onResult(boolean updateAvailable, String latestTag, String releaseUrl, boolean error);
    }

    private static final String API_URL =
            "https://api.github.com/repos/miyoubi/CVE-2023-33107/releases/latest";
    private static final String RELEASES_URL =
            "https://github.com/miyoubi/CVE-2023-33107/releases";
    private static final Pattern VER = Pattern.compile("(\\d+)");

    private UpdateChecker() {}

    static void check(Context ctx, Callback cb) {
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) new URL(API_URL).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                conn.setRequestProperty("Accept", "application/vnd.github+json");
                conn.setRequestProperty("User-Agent", "Fracture-App");
                int code = conn.getResponseCode();
                if (code != 200) {
                    cb.onResult(false, null, RELEASES_URL, true);
                    return;
                }
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                }
                JSONObject obj = new JSONObject(sb.toString());
                String tag = obj.optString("tag_name", null);
                String url = obj.optString("html_url", RELEASES_URL);
                if (url == null || url.isEmpty()) url = RELEASES_URL;

                String current = "0";
                try {
                    PackageInfo pi = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0);
                    if (pi.versionName != null) current = pi.versionName;
                } catch (Exception ignored) {
                }
                boolean newer = isNewer(tag, current);
                cb.onResult(newer, tag, url, false);
            } catch (Throwable t) {
                cb.onResult(false, null, RELEASES_URL, true);
            } finally {
                if (conn != null) conn.disconnect();
            }
        }, "update-check").start();
    }

    static boolean isNewer(String latestTag, String currentVersion) {
        if (latestTag == null) return false;
        int[] l = parse(latestTag);
        int[] c = parse(currentVersion);
        int n = Math.max(l.length, c.length);
        for (int i = 0; i < n; i++) {
            int lv = i < l.length ? l[i] : 0;
            int cv = i < c.length ? c[i] : 0;
            if (lv > cv) return true;
            if (lv < cv) return false;
        }
        // same numeric version: treat a tagged release (e.g. v2.0) as newer than a dev/unknown tagless build? no
        return false;
    }

    private static int[] parse(String v) {
        if (v == null) return new int[]{0};
        Matcher m = VER.matcher(v);
        java.util.ArrayList<Integer> parts = new java.util.ArrayList<>();
        while (m.find()) {
            try {
                parts.add(Integer.parseInt(m.group(1)));
            } catch (Exception ignored) {
            }
        }
        if (parts.isEmpty()) return new int[]{0};
        int[] out = new int[parts.size()];
        for (int i = 0; i < parts.size(); i++) out[i] = parts.get(i);
        return out;
    }
}