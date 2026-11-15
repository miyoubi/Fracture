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
    private static final String API_RELEASES = "https://api.github.com/repos/" + REPO + "/releases?per_page=10";
    private static final String API_COMMITS = "https://api.github.com/repos/" + REPO + "/commits?per_page=7";
    private static final Pattern VER = Pattern.compile("(\\d+)");

    interface Callback {
        void onResult(Result result);
    }

    static final class CommitInfo {
        final String sha;      // short, for display
        final String fullSha;
        final String message;
        final String date;
        final String author;
        CommitInfo(String sha, String fullSha, String message, String date, String author) {
            this.sha = sha;
            this.fullSha = fullSha;
            this.message = message;
            this.date = date;
            this.author = author;
        }
    }

    static final class Result {
        final boolean updateAvailable;
        final String latestTag;
        final String releaseUrl;
        final String downloadUrl;
        final String releaseName;
        final String releaseBody;
        final String publishedAt;
        final String currentVersion;
        final String currentBuild;
        final List<CommitInfo> commits;
        final boolean releaseError;
        final boolean commitsError;
        final boolean commitBased;
        final String latestCommitSha; // short

        Result(boolean updateAvailable, String latestTag, String releaseUrl, String downloadUrl, String releaseName,
               String releaseBody, String publishedAt, String currentVersion, String currentBuild,
               List<CommitInfo> commits, boolean releaseError, boolean commitsError,
               boolean commitBased, String latestCommitSha) {
            this.updateAvailable = updateAvailable;
            this.latestTag = latestTag;
            this.releaseUrl = releaseUrl;
            this.downloadUrl = downloadUrl;
            this.releaseName = releaseName;
            this.releaseBody = releaseBody;
            this.publishedAt = publishedAt;
            this.currentVersion = currentVersion;
            this.currentBuild = currentBuild;
            this.commits = commits;
            this.releaseError = releaseError;
            this.commitsError = commitsError;
            this.commitBased = commitBased;
            this.latestCommitSha = latestCommitSha;
        }

        boolean hasError() { return releaseError && commitsError; }
    }

    private UpdateChecker() {}

    static void check(Context ctx, Callback cb) {
        new Thread(() -> cb.onResult(fetch(ctx)), "update-check").start();
    }

    static Result fetch(Context ctx) {
        String current = getCurrentVersion(ctx);
        String currentBuild = BuildConfig.GIT_SHA;
        boolean includePrereleases = false;
        try {
            includePrereleases = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)
                    .getBoolean("include_prereleases", false);
        } catch (Exception ignored) {
        }
        String latestTag = null, releaseUrl = RELEASES_URL, downloadUrl = null, releaseName = null, releaseBody = null, publishedAt = null;
        boolean updateAvailable = false, releaseError = false, commitsError = false;
        boolean commitBased = false;
        String latestCommitSha = null;
        List<CommitInfo> commits = new ArrayList<>();

        // Latest release (stable: primary comparison; nightly/pre-release: metadata/fallback)
        try {
            JSONObject obj = null;
            if (includePrereleases) {
                String json = httpGet(API_RELEASES);
                if (json != null) {
                    JSONArray arr = new JSONArray(json);
                    for (int i = 0; i < arr.length(); i++) {
                        JSONObject r = arr.optJSONObject(i);
                        if (r == null) continue;
                        if (r.optBoolean("draft", false)) continue;
                        obj = r;
                        break;
                    }
                }
            } else {
                String json = httpGet(API_LATEST);
                if (json != null) obj = new JSONObject(json);
            }
            if (obj != null) {
                latestTag = optStr(obj, "tag_name");
                releaseUrl = optStr(obj, "html_url");
                if (releaseUrl == null || releaseUrl.isEmpty()) releaseUrl = RELEASES_URL;
                downloadUrl = pickDownloadUrl(obj);
                releaseName = optStr(obj, "name");
                releaseBody = optStr(obj, "body");
                publishedAt = optStr(obj, "published_at");
                if (!includePrereleases) {
                    updateAvailable = isNewer(latestTag, current, false);
                }
            } else {
                releaseError = true;
            }
        } catch (Throwable t) {
            releaseError = true;
        }

        // Commits (changelog; nightly/pre-release: primary comparison)
        try {
            String json = httpGet(API_COMMITS);
            if (json != null) {
                JSONArray arr = new JSONArray(json);
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject c = arr.optJSONObject(i);
                    if (c == null) continue;
                    String fullSha = optStr(c, "sha");
                    String sha = fullSha;
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
                        commits.add(new CommitInfo(sha != null ? sha : "", fullSha, msg != null ? msg : "", date, author));
                    }
                }
            } else {
                commitsError = true;
            }
        } catch (Throwable t) {
            commitsError = true;
        }

        // Nightly/pre-release mode: compare against latest commit when possible
        if (includePrereleases) {
            if (!commits.isEmpty() && isValidBuildSha(currentBuild)) {
                CommitInfo head = commits.get(0);
                latestCommitSha = head.sha;
                commitBased = true;
                updateAvailable = !isSameCommit(head.fullSha, currentBuild);
                if (latestCommitSha != null && !latestCommitSha.isEmpty()) {
                    latestTag = latestCommitSha;
                }
                if (head.message != null && !head.message.isEmpty()) {
                    releaseName = head.message;
                }
            } else {
                updateAvailable = isNewer(latestTag, current, true);
            }
        }

        return new Result(updateAvailable, latestTag, releaseUrl, downloadUrl, releaseName, releaseBody,
                publishedAt, current, currentBuild, commits, releaseError, commitsError,
                commitBased, latestCommitSha);
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

    private static boolean isValidBuildSha(String sha) {
        return sha != null && !sha.isEmpty() && !"unknown".equalsIgnoreCase(sha);
    }

    private static boolean isSameCommit(String remoteFull, String localBuildSha) {
        if (remoteFull == null || localBuildSha == null) return false;
        String r = remoteFull.trim().toLowerCase();
        String l = localBuildSha.trim().toLowerCase();
        if (r.isEmpty() || l.isEmpty()) return false;
        return r.startsWith(l) || l.startsWith(r) || r.equals(l);
    }

    private static String pickDownloadUrl(JSONObject releaseObj) {
        if (releaseObj == null) return null;
        JSONArray assets = releaseObj.optJSONArray("assets");
        if (assets == null || assets.length() == 0) return null;
        String fallback = null;
        for (int i = 0; i < assets.length(); i++) {
            JSONObject a = assets.optJSONObject(i);
            if (a == null) continue;
            String url = optStr(a, "browser_download_url");
            if (url == null) continue;
            String name = optStr(a, "name");
            if (fallback == null) fallback = url;
            if (name != null && name.toLowerCase().endsWith(".apk")) return url;
        }
        return fallback;
    }

    private static String optStr(JSONObject obj, String key) {
        if (obj == null) return null;
        String v = obj.optString(key, null);
        if (v == null || "null".equals(v) || v.isEmpty()) return null;
        return v;
    }

    static boolean isNewer(String latestTag, String currentVersion) {
        return isNewer(latestTag, currentVersion, false);
    }

    static boolean isNewer(String latestTag, String currentVersion, boolean includePrereleases) {
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
        if (includePrereleases) {
            String ln = normalizeTag(latestTag);
            String cn = normalizeTag(currentVersion);
            if (ln != null && !ln.equals(cn)) return true;
        }
        return false;
    }

    private static String normalizeTag(String v) {
        if (v == null) return null;
        String s = v.trim();
        if (s.startsWith("v") || s.startsWith("V")) s = s.substring(1);
        return s;
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