package com.cyberwise.exception;

/**
 * Custom checked exception for input validation errors (Lectures 10-12).
 */
public class InvalidInputException extends Exception {
    private final String inputField;

    public InvalidInputException(String message, String inputField) {
        super(message);
        this.inputField = inputField;
    }

    public String getInputField() {
        return inputField;
    }
}

