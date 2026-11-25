package com.cyberwise.analyzer;

import com.cyberwise.exception.InvalidInputException;

/**
 * Factory creating concrete {@code ThreatAnalyzer} instances based on requested scan type.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2A):</b>
 * Polymorphism (returning {@code ThreatAnalyzer} interface reference),
 * {@code static} factory method, {@code throw} / {@code throws} exception propagation.</p>
 */
public final class AnalyzerFactory {

    private AnalyzerFactory() {
    }

    /**
     * Returns an appropriate {@code ThreatAnalyzer} implementation for the given scan type.
     *
     * @param scanType LINK, SMS, or EMAIL
     * @return concrete ThreatAnalyzer instance
     * @throws InvalidInputException if scanType is unrecognized
     */
    public static ThreatAnalyzer getAnalyzer(String scanType) throws InvalidInputException {
        if (scanType == null) {
            throw new InvalidInputException("Scan type cannot be null.", "SCAN_TYPE");
        }
        String normalized = scanType.trim().toUpperCase();
        if ("LINK".equals(normalized) || "URL".equals(normalized)) {
            return new LinkAnalyzer();
        }
        if ("SMS".equals(normalized) || "TEXT".equals(normalized)) {
            return new SmsTextAnalyzer();
        }
        if ("EMAIL".equals(normalized)) {
            return new EmailAnalyzer();
        }
        throw new InvalidInputException("Unsupported scan type: " + scanType, "SCAN_TYPE");
    }
}
