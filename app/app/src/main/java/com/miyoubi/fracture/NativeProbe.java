package com.miyoubi.fracture;

final class NativeProbe {
    static {
        try {
            System.loadLibrary("fracture_native");
        } catch (Throwable ignored) {
        }
    }

    private NativeProbe() {}

    static native boolean isKernelSuActive();

    static boolean safeIsKernelSuActive() {
        try {
            return isKernelSuActive();
        } catch (Throwable ignored) {
            return false;
        }
    }
}
