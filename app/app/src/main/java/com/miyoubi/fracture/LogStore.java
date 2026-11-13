package com.miyoubi.fracture;

/** Simple in-process log buffer shared between activities. */
final class LogStore {
    private static final StringBuilder LOG = new StringBuilder();
    private static final int MAX = 200_000;

    private LogStore() {}

    static synchronized void append(String line) {
        LOG.append(line).append('\n');
        if (LOG.length() > MAX) {
            LOG.delete(0, LOG.length() - MAX);
        }
    }

    static synchronized String getDetailed() {
        return LOG.toString();
    }

    static synchronized String getSimple() {
        String text = LOG.toString();
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
