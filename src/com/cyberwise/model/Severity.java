package com.cyberwise.model;

/**
 * Constants and helper methods for red-flag severity tiers.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 1B):</b>
 * {@code static} members, Wrapper class {@code Integer}, String comparison.</p>
 */
public final class Severity {

    public static final String LOW = "LOW";
    public static final String MEDIUM = "MEDIUM";
    public static final String HIGH = "HIGH";
    public static final String CRITICAL = "CRITICAL";

    private Severity() {
    }

    /**
     * Returns a numeric priority rank (1-4) for sorting or matrix lookup.
     *
     * @param severity severity constant
     * @return numeric rank
     */
    public static int rank(String severity) {
        if (CRITICAL.equals(severity)) return 4;
        if (HIGH.equals(severity)) return 3;
        if (MEDIUM.equals(severity)) return 2;
        return 1;
    }

    /**
     * Infers severity tier from a rule weight using Integer wrapper comparison.
     *
     * @param weight rule weight
     * @return matching severity constant
     */
    public static String fromWeight(int weight) {
        Integer boxedWeight = Integer.valueOf(weight);
        if (boxedWeight >= 40) return CRITICAL;
        if (boxedWeight >= 25) return HIGH;
        if (boxedWeight >= 15) return MEDIUM;
        return LOW;
    }
}
