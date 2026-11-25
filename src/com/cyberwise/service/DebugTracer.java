package com.cyberwise.service;

/**
 * Provides toggleable step-by-step diagnostic logging for debugging analyzer decisions.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2A):</b>
 * {@code static} state flag, {@code StringBuffer} log accumulation,
 * Debugging trace visibility.</p>
 */
public final class DebugTracer {

    private static boolean debugEnabled = false;
    private static final StringBuffer SESSION_TRACE = new StringBuffer();

    private DebugTracer() {
    }

    public static boolean isDebugEnabled() {
        return debugEnabled;
    }

    public static void setDebugEnabled(boolean enabled) {
        debugEnabled = enabled;
        log("DebugTracer", "Debug trace mode " + (enabled ? "ENABLED" : "DISABLED"));
    }

    public static void toggle() {
        setDebugEnabled(!debugEnabled);
    }

    public static void log(String component, String message) {
        String line = String.format("[DEBUG][%s] %s", component, message);
        SESSION_TRACE.append(line).append("\n");
        if (debugEnabled) {
            System.out.println("\u001B[2m" + line + "\u001B[0m");
        }
    }

    public static String getSessionTrace() {
        return SESSION_TRACE.toString();
    }
}
