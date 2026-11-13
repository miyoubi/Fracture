package com.miyoubi.fracture;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Simple in-process log buffer shared between activities. */
final class LogStore {
    private static final StringBuilder LOG = new StringBuilder();
    private static final StringBuilder LOG_TS = new StringBuilder();
    private static final int MAX = 200_000;
    private static final ThreadLocal<SimpleDateFormat> TS_FMT = new ThreadLocal<SimpleDateFormat>() {
        @Override protected SimpleDateFormat initialValue() {
            return new SimpleDateFormat("HH:mm:ss", Locale.US);
        }
    };

    private LogStore() {}

    private static String ts() {
        return TS_FMT.get().format(new Date());
    }

    static synchronized void append(String line) {
        String t = ts();
        LOG.append(line).append('\n');
        LOG_TS.append('[').append(t).append("] ").append(line).append('\n');
        if (LOG.length() > MAX) {
            LOG.delete(0, LOG.length() - MAX);
        }
        if (LOG_TS.length() > MAX) {
            LOG_TS.delete(0, LOG_TS.length() - MAX);
        }
    }

    static synchronized String getDetailed() {
        return LOG.toString();
    }

    static synchronized String getDetailed(boolean timestamps) {
        return timestamps ? LOG_TS.toString() : LOG.toString();
    }

    static synchronized String getSimple() {
        return getSimple(false);
    }

    static synchronized String getSimple(boolean timestamps) {
        String text = timestamps ? LOG_TS.toString() : LOG.toString();
        if (text.isEmpty()) return text;
        String[] lines = text.split("\n", -1);
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            if (line.isEmpty()) continue;
            if (isSimpleLine(line)) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    static synchronized void clear() {
        LOG.setLength(0);
        LOG_TS.setLength(0);
    }

    static synchronized boolean isEmpty() {
        return LOG.length() == 0;
    }

    static boolean isSimpleLine(String line) {
        String l = line;
        if (l.startsWith("—") || l.contains("—")) return true;
        String lower = l.toLowerCase();
        return lower.contains("staging")
                || lower.contains("running exploit")
                || lower.contains("exploit exited")
                || lower.contains("restoring enforcing")
                || lower.contains("skipping selinux")
                || lower.contains("soft reboot")
                || lower.contains("kernelSU is already live")
                || lower.contains("kernelsu")
                || lower.contains("error")
                || lower.contains("failed")
                || lower.contains("fail")
                || lower.contains("not running the exploit")
                || lower.contains("grant shizuku")
                || lower.contains("no payload profile")
                || lower.contains("not detected")
                || lower.contains("manager not found")
                || lower.contains("could not open");
    }
}
