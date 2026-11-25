package com.cyberwise.exception;

/**
 * Base checked custom exception for CyberWise.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A):</b>
 * Checked Exceptions, Custom Exceptions, Constructor Chaining with {@code super},
 * {@code this} keyword, and Exception Propagation.</p>
 */
public class CyberWiseException extends Exception {

    private final String errorCode;

    /**
     * Constructs a new CyberWiseException with a message and error code.
     *
     * @param message   human-readable explanation of the error
     * @param errorCode short application error code
     */
    public CyberWiseException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Overloaded constructor supporting exception chaining.
     *
     * @param message   human-readable explanation
     * @param errorCode short application error code
     * @param cause     underlying cause
     */
    public CyberWiseException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return this.errorCode;
    }
}
