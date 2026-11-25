package com.cyberwise.service;

import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.exception.ScanLimitExceededException;
import com.cyberwise.exception.UnknownMenuOptionException;

/**
 * Centralizes console and payload input validation using Wrapper classes and custom exceptions.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B & Unit 2A):</b>
 * Wrapper classes ({@code Integer.parseInt}, {@code Character.isWhitespace}),
 * {@code throw} and {@code throws}, Checked Exceptions ({@code InvalidInputException},
 * {@code UnknownMenuOptionException}), Unchecked Exception ({@code ScanLimitExceededException}).</p>
 */
public final class InputValidator {

    public static final int MAX_URL_LENGTH = 2048;
    public static final int MAX_TEXT_LENGTH = 5000;

    private InputValidator() {
    }

    /**
     * Validates that a text payload is non-null, non-blank, and within maximum length.
     *
     * @param input     raw text or URL
     * @param fieldName label for exception message
     * @return trimmed valid string
     * @throws InvalidInputException if input is null or blank
     */
    public static String validateNonEmpty(String input, String fieldName) throws InvalidInputException {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidInputException(fieldName + " cannot be empty.", fieldName);
        }
        String trimmed = input.trim();
        int maxLen = "URL".equalsIgnoreCase(fieldName) ? MAX_URL_LENGTH : MAX_TEXT_LENGTH;
        if (trimmed.length() > maxLen) {
            throw new ScanLimitExceededException(trimmed.length(), maxLen);
        }
        return trimmed;
    }

    /**
     * Validates basic URL structure (no internal spaces, contains at least one dot or scheme).
     *
     * @param rawUrl candidate URL string
     * @return trimmed valid URL
     * @throws InvalidInputException if URL is empty or malformed
     */
    public static String validateUrl(String rawUrl) throws InvalidInputException {
        String trimmed = validateNonEmpty(rawUrl, "URL");
        for (int i = 0; i < trimmed.length(); i++) {
            if (Character.isWhitespace(trimmed.charAt(i))) {
                throw new InvalidInputException("URL must not contain spaces or whitespace.", "URL");
            }
        }
        if (!trimmed.contains(".") && !trimmed.toLowerCase().startsWith("http")) {
            throw new InvalidInputException(
                    "Invalid URL format. Example: https://sbi.co.in or http://sbi-kyc.xyz", "URL");
        }
        return trimmed;
    }

    /**
     * Parses and validates a menu selection using {@code Integer.parseInt}.
     *
     * @param rawChoice user input string
     * @param min       minimum valid integer option
     * @param max       maximum valid integer option
     * @return parsed choice integer
     * @throws UnknownMenuOptionException if choice is outside allowed range
     */
    public static int parseMenuChoice(String rawChoice, int min, int max)
            throws UnknownMenuOptionException {
        if (rawChoice == null || rawChoice.trim().isEmpty()) {
            throw new UnknownMenuOptionException("");
        }
        String trimmed = rawChoice.trim();
        int parsed = Integer.parseInt(trimmed); // May throw NumberFormatException (unchecked)
        if (parsed < min || parsed > max) {
            throw new UnknownMenuOptionException(trimmed);
        }
        return parsed;
    }
}
