package com.cyberwise.engine;

import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScanResult;
import com.cyberwise.model.Severity;
import com.cyberwise.model.VerdictConstants;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * Computes overall risk scores and primary scam categories using a 2D risk calibration matrix.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B & Unit 2B):</b>
 * Multi-dimensional Arrays ({@code int[][]} and {@code String[][]}),
 * {@code HashMap} for category score aggregation, {@code Wrapper} classes ({@code Integer}).</p>
 */
public final class RiskScoringMatrix {

    /**
     * 2D Risk Matrix: rows = Severity (LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3),
     * columns = Flag Count Tier (1 flag=0, 2 flags=1, 3+ flags=2).
     * Value represents minimum baseline floor score when multiple serious flags appear.
     */
    private static final int[][] BASELINE_FLOOR_MATRIX = {
        {10, 18, 25}, // LOW
        {20, 35, 50}, // MEDIUM
        {35, 60, 75}, // HIGH
        {45, 75, 90}  // CRITICAL
    };

    /**
     * 2D Score Band Legend Table for display formatting.
     */
    private static final String[][] VERDICT_BANDS = {
        {"0 - 30",   VerdictConstants.SAFE,       "Low Risk (No strong scam signals)"},
        {"31 - 65",  VerdictConstants.SUSPICIOUS, "Moderate Risk (Verify via official app/site)"},
        {"66 - 100", VerdictConstants.DANGEROUS,  "High Risk (Likely fraud — block & report)"}
    };

    private RiskScoringMatrix() {
    }

    /**
     * Finalizes the risk score, verdict, primary category, and summary of a {@code ScanResult}.
     *
     * @param result scan result containing collected RedFlags
     */
    public static void finalizeScore(ScanResult result) {
        ArrayList<RedFlag> flags = result.getRedFlags();
        if (flags.isEmpty()) {
            result.setRiskScore(0);
            result.setPrimaryCategory(ScamCategory.SAFE_GENERAL);
            result.setSummary("No suspicious keywords, fake domains, or scam patterns were detected.");
            return;
        }

        int rawTotal = 0;
        int highestSeverityIdx = 0;
        HashMap<String, Integer> categoryScores = new HashMap<String, Integer>();

        for (int i = 0; i < flags.size(); i++) {
            RedFlag flag = flags.get(i);
            rawTotal += flag.getWeight();

            int sevIdx = Severity.rank(flag.getSeverity()) - 1;
            if (sevIdx > highestSeverityIdx) {
                highestSeverityIdx = sevIdx;
            }

            String cat = flag.getCategory();
            Integer existing = categoryScores.get(cat);
            int updated = (existing == null ? 0 : existing.intValue()) + flag.getWeight();
            categoryScores.put(cat, Integer.valueOf(updated));
        }

        int countTier = Math.min(2, flags.size() - 1);
        int floorScore = BASELINE_FLOOR_MATRIX[highestSeverityIdx][countTier];
        int finalScore = Math.min(100, Math.max(rawTotal, floorScore));
        result.setRiskScore(finalScore);

        String topCategory = determinePrimaryCategory(categoryScores);
        result.setPrimaryCategory(topCategory);

        result.setSummary(String.format(
                "Detected %d red flag(s) across %d scam vector(s). Primary classification: %s.",
                flags.size(), result.getTriggeredCategories().size(), ScamCategory.toDisplayName(topCategory)));
    }

    private static String determinePrimaryCategory(HashMap<String, Integer> categoryScores) {
        String topCat = ScamCategory.SAFE_GENERAL;
        int bestWeight = -1;
        for (String cat : categoryScores.keySet()) {
            int score = categoryScores.get(cat).intValue();
            if (score > bestWeight) {
                bestWeight = score;
                topCat = cat;
            }
        }
        return topCat;
    }

    public static String[][] getVerdictBands() {
        return VERDICT_BANDS;
    }
}
