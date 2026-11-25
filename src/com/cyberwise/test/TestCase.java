package com.cyberwise.test;

/**
 * Domain object describing a single automated test case in CyberWise.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2A):</b>
 * Encapsulation, Overloaded Constructors, Test Cases.</p>
 */
public class TestCase {

    private final String testName;
    private final String scanType;
    private final String payload;
    private final String expectedVerdict;
    private final int minExpectedScore;
    private final int maxExpectedScore;

    public TestCase(String testName, String scanType, String payload,
                    String expectedVerdict, int minExpectedScore, int maxExpectedScore) {
        this.testName = testName;
        this.scanType = scanType;
        this.payload = payload;
        this.expectedVerdict = expectedVerdict;
        this.minExpectedScore = minExpectedScore;
        this.maxExpectedScore = maxExpectedScore;
    }

    public String getTestName() {
        return this.testName;
    }

    public String getScanType() {
        return this.scanType;
    }

    public String getPayload() {
        return this.payload;
    }

    public String getExpectedVerdict() {
        return this.expectedVerdict;
    }

    public int getMinExpectedScore() {
        return this.minExpectedScore;
    }

    public int getMaxExpectedScore() {
        return this.maxExpectedScore;
    }
}
