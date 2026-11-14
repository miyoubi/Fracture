package com.miyoubi.fracture;

import android.content.Context;
import android.content.pm.PackageInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class UpdateChecker {
    static final String REPO = "miyoubi/CVE-2023-33107";
    static final String RELEASES_URL = "https://github.com/" + REPO + "/releases";
    private static final String API_LATEST = "https://api.github.com/repos/" + REPO + "/releases/latest";
    private static final String API_COMMITS = "https://api.github.com/repos/" + REPO + "/commits?per_page=7";
    private static final Pattern VER = Pattern.compile("(\\d+)");

    interface Callback {
        void onResult(Result result);
    }

    static final class CommitInfo {
        final String sha;
        final String message;
        final String date;
        final String author;
        CommitInfo(String sha, String message, String date, String author) {
            this.sha = sha;
            this.message = message;
            this.date = date;
            this.author = author;
        }
    }

    static final class Result {
        final boolean updateAvailable;
        final String latestTag;
        final String releaseUrl;
        final String releaseName;
        final String releaseBody;
        final String publishedAt;
        final String currentVersion;
        final List<CommitInfo> commits;
        final boolean releaseError;
        final boolean commitsError;

        Result(boolean updateAvailable, String latestTag, String releaseUrl, String releaseName,
               String releaseBody, String publishedAt, String currentVersion,
               List<CommitInfo> commits, boolean releaseError, boolean commitsError) {
            this.updateAvailable = updateAvailable;
            this.latestTag = latestTag;
            this.releaseUrl = releaseUrl;
            this.releaseName = releaseName;
            this.releaseBody = releaseBody;
            this.publishedAt = publishedAt;
            this.currentVersion = currentVersion;
            this.commits = commits;
            this.releaseError = releaseError;
            this.commitsError = commitsError;
        }

        boolean hasError() { return releaseError && commitsError; }
    }

    private UpdateChecker() {}

    static void check(Context ctx, Callback cb) {
        new Thread(() -> cb.onResult(fetch(ctx)), "update-check").start();
    }

    static Result fetch(Context ctx) {
        String current = getCurrentVersion(ctx);
        String latestTag = null, releaseUrl = RELEASES_URL, releaseName = null, releaseBody = null, publishedAt = null;
        boolean updateAvailable = false, releaseError = false, commitsError = false;
        List<CommitInfo> commits = new ArrayList<>();

        // Latest release
        try {
            String json = httpGet(API_LATEST);
            if (json != null) {
                JSONObject obj = new JSONObject(json);
                latestTag = optStr(obj, "tag_name");
                releaseUrl = optStr(obj, "html_url");
                if (releaseUrl == null || releaseUrl.isEmpty()) releaseUrl = RELEASES_URL;
                releaseName = optStr(obj, "name");
                releaseBody = optStr(obj, "body");
                publishedAt = optStr(obj, "published_at");
                updateAvailable = isNewer(latestTag, current);
            } else {
                releaseError = true;
            }
        } catch (Throwable t) {
            releaseError = true;
        }

        // Commits (changelog)
        try {
            String json = httpGet(API_COMMITS);
            if (json != null) {
                JSONArray arr = new JSONArray(json);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject c = arr.optJSONObject(i);
                    if (c == null) continue;
                    String sha = optStr(c, "sha");
                    if (sha != null && sha.length() > 7) sha = sha.substring(0, 7);
                    String msg = null, date = null, author = null;
                    JSONObject commit = c.optJSONObject("commit");
                    if (commit != null) {
                        msg = optStr(commit, "message");
                        if (msg != null) {
                            int nl = msg.indexOf('\n');
                            if (nl > 0) msg = msg.substring(0, nl);
                            msg = msg.trim();
                        }
                        JSONObject ca = commit.optJSONObject("author");
                        if (ca != null) {
                            author = optStr(ca, "name");
                            date = optStr(ca, "date");
                        }
                    }
                    if (author == null) {
                        JSONObject au = c.optJSONObject("author");
                        if (au != null) author = optStr(au, "login");
                    }
                    if (msg != null || sha != null) {
                        commits.add(new CommitInfo(sha != null ? sha : "", msg != null ? msg : "", date, author));
                    }
                }
            } else {
                commitsError = true;
            }
        } catch (Throwable t) {
            commitsError = true;
        }

        return new Result(updateAvailable, latestTag, releaseUrl, releaseName, releaseBody,
                publishedAt, current, commits, releaseError, commitsError);
    }

    private static String httpGet(String urlStr) throws Exception {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "Fracture-App");
            int code = conn.getResponseCode();
            if (code != 200) return null;
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
            }
            return sb.toString();
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String getCurrentVersion(Context ctx) {
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageInfo(ctx.getPackageName(), 0);
            if (pi.versionName != null) return pi.versionName;
        } catch (Exception ignored) {
        }
        return "0";
    }

    private static String optStr(JSONObject obj, String key) {
        if (obj == null) return null;
        String v = obj.optString(key, null);
        if (v == null || "null".equals(v) || v.isEmpty()) return null;
        return v;
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
        return false;
    }

    private static int[] parse(String v) {
        if (v == null) return new int[]{0};
        Matcher m = VER.matcher(v);
        ArrayList<Integer> parts = new ArrayList<>();
        while (m.find()) {
            try { parts.add(Integer.parseInt(m.group(1))); } catch (Exception ignored) {}
        }
        if (parts.isEmpty()) return new int[]{0};
        int[] out = new int[parts.size()];
        for (int i = 0; i < parts.size(); i++) out[i] = parts.get(i);
        return out;
    }
}