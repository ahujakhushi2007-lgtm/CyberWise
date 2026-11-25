package com.cyberwise.analyzer;

import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.model.ScanResult;

/**
 * Contract for all threat analyzers in CyberWise.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2A):</b>
 * Interfaces, Abstraction, Polymorphism, Exception Propagation ({@code throws CyberWiseException}).</p>
 */
public interface ThreatAnalyzer {

    /**
     * Analyzes the provided payload and returns a populated {@code ScanResult}.
     *
     * @param input raw URL, SMS, or email content
     * @return completed scan result with score, verdict, and red flags
     * @throws CyberWiseException if validation or analysis fails
     */
    ScanResult analyze(String input) throws CyberWiseException;

    /**
     * Returns the human-readable analyzer name.
     */
    String getAnalyzerName();

    /**
     * Returns the scan type label supported by this analyzer (e.g., LINK, SMS, EMAIL).
     */
    String getSupportedType();
}
