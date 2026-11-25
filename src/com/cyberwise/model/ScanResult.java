package com.cyberwise.model;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.TreeSet;

/**
 * Encapsulates the complete forensic result of scanning a URL, SMS, or Email.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2B):</b>
 * {@code static} scan counter, Encapsulation, Method Overloading ({@code addRedFlag}),
 * {@code ArrayList}, {@code LinkedHashSet}, and {@code TreeSet}.</p>
 */
public class ScanResult {

    private static int nextScanId = 1;

    private final int scanId;
    private final String scanType;
    private final String originalInput;
    private int riskScore;
    private String verdict;
    private String primaryCategory;
    private String summary;
    private final ArrayList<RedFlag> redFlags;
    private final LinkedHashSet<String> triggeredCategories;
    private final TreeSet<String> uniqueMatchedTokens;
    private final ArrayList<String> nextSteps;
    private final StringBuffer traceLog;

    public ScanResult(String scanType, String originalInput) {
        this.scanId = nextScanId++;
        this.scanType = scanType;
        this.originalInput = originalInput;
        this.riskScore = 0;
        this.verdict = VerdictConstants.SAFE;
        this.primaryCategory = ScamCategory.SAFE_GENERAL;
        this.summary = "";
        this.redFlags = new ArrayList<RedFlag>();
        this.triggeredCategories = new LinkedHashSet<String>();
        this.uniqueMatchedTokens = new TreeSet<String>();
        this.nextSteps = new ArrayList<String>();
        this.traceLog = new StringBuffer();
    }

    /**
     * Method Overloading #1: Adds a pre-built RedFlag object.
     */
    public void addRedFlag(RedFlag flag) {
        this.redFlags.add(flag);
        this.triggeredCategories.add(flag.getCategory());
        if (flag.getMatchedText() != null && !flag.getMatchedText().trim().isEmpty()) {
            this.uniqueMatchedTokens.add(flag.getMatchedText().toLowerCase().trim());
        }
        this.traceLog.append("[FLAG] ").append(flag.getRuleId())
                .append(" (+").append(flag.getWeight()).append(")\n");
    }

    /**
     * Method Overloading #2: Convenience overload creating and adding a RedFlag directly.
     */
    public void addRedFlag(String ruleId, String ruleName, String category,
                           String severity, int weight, String matchedText, String explanation) {
        RedFlag flag = new RedFlag(ruleId, ruleName, category, severity, weight, matchedText, explanation);
        this.addRedFlag(flag);
    }

    public static int getTotalScansCreated() {
        return nextScanId - 1;
    }

    public int getScanId() {
        return this.scanId;
    }

    public String getScanType() {
        return this.scanType;
    }

    public String getOriginalInput() {
        return this.originalInput;
    }

    public int getRiskScore() {
        return this.riskScore;
    }

    public void setRiskScore(int riskScore) {
        if (riskScore < 0) {
            this.riskScore = 0;
        } else if (riskScore > 100) {
            this.riskScore = 100;
        } else {
            this.riskScore = riskScore;
        }
        this.verdict = VerdictConstants.fromScore(this.riskScore);
    }

    public String getVerdict() {
        return this.verdict;
    }

    public String getPrimaryCategory() {
        return this.primaryCategory;
    }

    public void setPrimaryCategory(String primaryCategory) {
        this.primaryCategory = primaryCategory;
    }

    public String getSummary() {
        return this.summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public ArrayList<RedFlag> getRedFlags() {
        return this.redFlags;
    }

    public LinkedHashSet<String> getTriggeredCategories() {
        return this.triggeredCategories;
    }

    public TreeSet<String> getUniqueMatchedTokens() {
        return this.uniqueMatchedTokens;
    }

    public ArrayList<String> getNextSteps() {
        return this.nextSteps;
    }

    public void setNextSteps(ArrayList<String> steps) {
        this.nextSteps.clear();
        this.nextSteps.addAll(steps);
    }

    public StringBuffer getTraceLog() {
        return this.traceLog;
    }

    @Override
    public String toString() {
        return String.format("#%d | %-6s | Score: %3d/100 | %-10s | %s",
                this.scanId, this.scanType, this.riskScore, this.verdict,
                ScamCategory.toDisplayName(this.primaryCategory));
    }
}
