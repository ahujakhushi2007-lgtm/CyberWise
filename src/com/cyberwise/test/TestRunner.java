package com.cyberwise.test;

import com.cyberwise.cli.AnsiPalette;
import com.cyberwise.data.AwarenessRepository;
import com.cyberwise.engine.TextSimilarityEngine;
import com.cyberwise.exception.AwarenessNotFoundException;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.exception.ScanLimitExceededException;
import com.cyberwise.model.ScanResult;
import com.cyberwise.service.InputValidator;
import com.cyberwise.service.ScanService;

import java.util.ArrayList;

/**
 * Built-in Core Java test runner executing scan accuracy, exception handling,
 * 2D array edit-distance, and String Pool unit tests.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B, Unit 2A, Unit 2B):</b>
 * Test Cases, {@code try-catch-finally}, multi-catch, Checked & Unchecked Exceptions,
 * String Formatting ({@code String.format}), {@code ArrayList}.</p>
 */
public final class TestRunner {

    private TestRunner() {
    }

    /**
     * Runs all automated unit tests and prints a formatted summary report.
     *
     * @return true if every test passes
     */
    public static boolean runAll() {
        System.out.println("\n" + AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);
        System.out.println(AnsiPalette.BOLD + "  CYBERWISE UNIT TEST SUITE (CORE JAVA)" + AnsiPalette.RESET);
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);

        ArrayList<TestResult> results = new ArrayList<TestResult>();
        ScanService service = new ScanService();

        // 1. Run all scan accuracy test cases
        ArrayList<TestCase> cases = CyberWiseTestSuite.buildScanTestCases();
        for (int i = 0; i < cases.size(); i++) {
            TestCase tc = cases.get(i);
            try {
                ScanResult sr = service.runScan(tc.getScanType(), tc.getPayload());
                boolean verdictMatch = tc.getExpectedVerdict().equals(sr.getVerdict());
                boolean scoreInRange = sr.getRiskScore() >= tc.getMinExpectedScore()
                        && sr.getRiskScore() <= tc.getMaxExpectedScore();
                boolean ok = verdictMatch && scoreInRange;
                String detail = String.format("Score=%d, Verdict=%s (Expected %s [%d-%d])",
                        sr.getRiskScore(), sr.getVerdict(), tc.getExpectedVerdict(),
                        tc.getMinExpectedScore(), tc.getMaxExpectedScore());
                results.add(new TestResult(tc.getTestName(), ok, detail));
            } catch (CyberWiseException e) {
                results.add(new TestResult(tc.getTestName(), false, "Unexpected exception: " + e.getMessage()));
            }
        }

        // 2. Unit test: 2D array Levenshtein distance & homoglyph normalization
        int dist = TextSimilarityEngine.computeEditDistance("paytm", "paytn");
        String norm = TextSimilarityEngine.normalizeHomoglyphs("amaz0n");
        boolean simOk = (dist == 1) && "amazon".equals(norm);
        results.add(new TestResult("2D Matrix EditDistance & Homoglyph Normalization", simOk,
                "editDist('paytm','paytn')=" + dist + ", norm('amaz0n')='" + norm + "'"));

        // 3. Unit test: String Pool & Immutability verification
        String poolReport = TextSimilarityEngine.demonstrateStringPoolAndImmutability();
        boolean poolOk = poolReport.contains("StringPool(==): true")
                && poolReport.contains("Heap(==): false")
                && poolReport.contains("ImmutabilityVerified: true");
        results.add(new TestResult("String Pool (== vs .equals) & Immutability", poolOk, poolReport));

        // 4. Unit test: Checked InvalidInputException on blank URL
        boolean invalidCaught = false;
        try {
            InputValidator.validateUrl("   ");
        } catch (InvalidInputException e) {
            invalidCaught = true;
        }
        results.add(new TestResult("Checked Exception: InvalidInputException on blank URL",
                invalidCaught, "Caught InvalidInputException=" + invalidCaught));

        // 5. Unit test: Checked AwarenessNotFoundException on unknown ID
        boolean awarenessCaught = false;
        try {
            AwarenessRepository.getArticleById("999");
        } catch (AwarenessNotFoundException e) {
            awarenessCaught = true;
        }
        results.add(new TestResult("Checked Exception: AwarenessNotFoundException",
                awarenessCaught, "Caught AwarenessNotFoundException=" + awarenessCaught));

        // 6. Unit test: Unchecked ScanLimitExceededException on oversized input
        boolean limitCaught = false;
        StringBuilder oversized = new StringBuilder();
        for (int i = 0; i < 2100; i++) {
            oversized.append('a');
        }
        try {
            InputValidator.validateUrl(oversized.toString());
        } catch (ScanLimitExceededException | InvalidInputException e) {
            limitCaught = (e instanceof ScanLimitExceededException);
        }
        results.add(new TestResult("Unchecked Exception: ScanLimitExceededException",
                limitCaught, "Caught ScanLimitExceededException=" + limitCaught));

        // Print summary
        int passedCount = 0;
        for (int i = 0; i < results.size(); i++) {
            TestResult tr = results.get(i);
            if (tr.isPassed()) {
                passedCount++;
            }
            String badge = tr.isPassed()
                    ? AnsiPalette.GREEN + "[PASS]" + AnsiPalette.RESET
                    : AnsiPalette.BOLD_RED + "[FAIL]" + AnsiPalette.RESET;
            System.out.printf("  %s %-52s | %s%n", badge, tr.getTestName(), tr.getDetail());
        }

        System.out.println(AnsiPalette.CYAN
                + "----------------------------------------------------------------------"
                + AnsiPalette.RESET);
        String summaryColor = (passedCount == results.size()) ? AnsiPalette.GREEN : AnsiPalette.RED;
        System.out.printf("  Test Summary: %s%d / %d PASSED%s%n",
                summaryColor, passedCount, results.size(), AnsiPalette.RESET);
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);

        return passedCount == results.size();
    }
}
