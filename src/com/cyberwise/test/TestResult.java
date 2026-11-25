package com.cyberwise.test;

/**
 * Encapsulates the outcome of running one {@code TestCase}.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2A):</b>
 * Classes and Objects, Encapsulation, Test Cases.</p>
 */
public class TestResult {

    private final String testName;
    private final boolean passed;
    private final String detail;

    public TestResult(String testName, boolean passed, String detail) {
        this.testName = testName;
        this.passed = passed;
        this.detail = detail;
    }

    public String getTestName() {
        return this.testName;
    }

    public boolean isPassed() {
        return this.passed;
    }

    public String getDetail() {
        return this.detail;
    }
}
