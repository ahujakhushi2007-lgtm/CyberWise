package com.cyberwise.exception;

/**
 * Checked exception thrown when user input fails validation (empty, null, or malformed).
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A):</b>
 * Checked Custom Exceptions, Inheritance ({@code extends CyberWiseException}), Input Validation.</p>
 */
public class InvalidInputException extends CyberWiseException {

    private final String inputField;

    public InvalidInputException(String message, String inputField) {
        super(message, "ERR_INVALID_INPUT");
        this.inputField = inputField;
    }

    public InvalidInputException(String message, String inputField, Throwable cause) {
        super(message, "ERR_INVALID_INPUT", cause);
        this.inputField = inputField;
    }

    public String getInputField() {
        return this.inputField;
    }
}
