package com.cyberwise.model;

/**
 * Holds risk verdict constants and static classification helpers.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 1B):</b>
 * {@code static} constants and utility methods, String comparison, and conditional logic.</p>
 */
public final class VerdictConstants {

    public static final String SAFE = "SAFE";
    public static final String SUSPICIOUS = "SUSPICIOUS";
    public static final String DANGEROUS = "DANGEROUS";

    public static final int SAFE_MAX_SCORE = 30;
    public static final int SUSPICIOUS_MAX_SCORE = 65;

    private VerdictConstants() {
        // Prevent instantiation of utility constant class
    }

    /**
     * Maps a risk score (0-100) to a verdict constant.
     *
     * @param score risk score between 0 and 100
     * @return SAFE, SUSPICIOUS, or DANGEROUS
     */
    public static String fromScore(int score) {
        if (score <= SAFE_MAX_SCORE) {
            return SAFE;
        }
        if (score <= SUSPICIOUS_MAX_SCORE) {
            return SUSPICIOUS;
        }
        return DANGEROUS;
    }

    /**
     * Returns a short human-readable description for the given verdict.
     *
     * @param verdict verdict label
     * @return descriptive summary
     */
    public static String describe(String verdict) {
        if (SAFE.equals(verdict)) {
            return "Low risk — no significant scam indicators detected.";
        }
        if (SUSPICIOUS.equals(verdict)) {
            return "Moderate risk — verify through official channels before acting.";
        }
        return "High risk — strong fraud/scam indicators detected! Do not click or pay.";
    }
}
