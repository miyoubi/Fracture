package com.miyoubi.fracture;

import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import rikka.shizuku.Shizuku;

/** Runs commands as the shell (uid 2000) through Shizuku. */
final class ShizukuRunner {

    interface Listener {
        void line(String line);
    }

    private ShizukuRunner() {}

    private static Method processMethod;

    /*
     * Shizuku.newProcess is public in older API levels but hidden in 13.x;
     * call the same binder-backed method reflectively.
     */
    private static Process newProcess(String[] cmd, String[] env, String dir) throws Exception {
        Method method = processMethod;
        if (method == null) {
            method = Shizuku.class.getDeclaredMethod(
                    "newProcess", String[].class, String[].class, String.class);
            method.setAccessible(true);
            processMethod = method;
        }
        try {
            return (Process) method.invoke(null, cmd, env, dir);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw e;
        }
    }

    static boolean ready() {
        try {
            return Shizuku.pingBinder()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Write a payload to path (cat > path) and chmod it. */
    static int stage(String path, byte[] data, Listener listener) throws Exception {
        Process p = newProcess(new String[]{
                "sh", "-c", "cat > " + path + " && chmod 755 " + path
        }, null, "/data/local/tmp");
        try (OutputStream out = p.getOutputStream()) {
            out.write(data);
        }
        drain(p, listener);
        return p.waitFor();
    }

    /** Run a shell command with stdout and stderr merged, streaming lines. */
    static int exec(String command, Listener listener) throws Exception {
        Process p = newProcess(new String[]{
                "sh", "-c", command + " 2>&1"
        }, null, "/data/local/tmp");
        drain(p, listener);
        return p.waitFor();
    }

    private static void drain(Process p, Listener listener) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (listener != null) listener.line(line);
            }
        } catch (IOException ignored) {
        }
    }
}
