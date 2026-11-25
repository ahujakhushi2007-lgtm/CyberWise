package com.cyberwise.cli;

/**
 * Provides ANSI terminal color escape sequences for colored console output.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 1B):</b>
 * {@code static final} constants, String Pool literals, String concatenation helpers.</p>
 */
public final class AnsiPalette {

    public static final String RESET = "\u001B[0m";
    public static final String BOLD = "\u001B[1m";
    public static final String DIM = "\u001B[2m";

    public static final String RED = "\u001B[31m";
    public static final String BOLD_RED = "\u001B[1;31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String CYAN = "\u001B[36m";

    private AnsiPalette() {
    }

    public static String colorize(String text, String ansiCode) {
        return ansiCode + text + RESET;
    }
}
