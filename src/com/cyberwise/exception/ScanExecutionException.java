package com.cyberwise.exception;

/**
 * Custom unchecked runtime exception for scan pipeline execution failures (Lectures 10-12).
 */
public class ScanExecutionException extends RuntimeException {
    public ScanExecutionException(String message, Throwable cause) {
        super(message, cause);
    }

    public ScanExecutionException(String message) {
        super(message);
    }
}

