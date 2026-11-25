package com.cyberwise.exception;

/**
 * Unchecked exception thrown when an input exceeds safe processing limits or
 * an analyzer encounters an invalid internal configuration state.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A):</b>
 * Unchecked Exceptions ({@code extends RuntimeException}), Custom Exceptions.</p>
 */
public class ScanLimitExceededException extends RuntimeException {

    private final int maxAllowedLength;
    private final int actualLength;

    public ScanLimitExceededException(int actualLength, int maxAllowedLength) {
        super("Input length (" + actualLength + ") exceeds maximum allowed limit (" + maxAllowedLength + ").");
        this.actualLength = actualLength;
        this.maxAllowedLength = maxAllowedLength;
    }

    public int getMaxAllowedLength() {
        return this.maxAllowedLength;
    }

    public int getActualLength() {
        return this.actualLength;
    }
}
