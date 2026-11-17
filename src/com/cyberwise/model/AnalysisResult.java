package com.cyberwise.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Encapsulates security analysis outcomes and implements Comparable for sorting (Lectures 23-25).
 */
public class AnalysisResult implements Comparable<AnalysisResult> {
    private final String target;
    private final String artifactType; // "URL", "TEXT", "EMAIL"
    private int riskScore;
    private Verdict verdict;
    private final List<Finding> findings;
    private final List<String> tactics;
    private final List<String> recommendedActions;
    private String impersonatedBrand;
    private String scamType;
    private String explanation;
    private String explanationHi;
    private String mode;
    private final long timestamp;

    public AnalysisResult(String target, String artifactType) {
        this.target = target;
        this.artifactType = artifactType;
        this.riskScore = 0;
        this.verdict = Verdict.SAFE;
        this.findings = new ArrayList<>();
        this.tactics = new ArrayList<>();
        this.recommendedActions = new ArrayList<>();
        this.impersonatedBrand = null;
        this.scamType = null;
        this.explanation = "";
        this.explanationHi = "";
        this.mode = "Rule Engine (Offline)";
        this.timestamp = System.currentTimeMillis();
    }

    public String getTarget() { return target; }
    public String getArtifactType() { return artifactType; }
    public int getRiskScore() { return riskScore; }
    public long getTimestamp() { return timestamp; }

    public void setRiskScore(int score) {
        this.riskScore = Math.max(0, Math.min(100, score));
        if (this.riskScore >= 60) {
            this.verdict = Verdict.DANGEROUS;
        } else if (this.riskScore >= 20) {
            this.verdict = Verdict.SUSPICIOUS;
        } else {
            this.verdict = Verdict.SAFE;
        }
    }

    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }

    public List<Finding> getFindings() { return findings; }
    public void addFinding(Finding finding) { this.findings.add(finding); }

    public List<String> getTactics() { return tactics; }
    public void addTactic(String tactic) {
        if (!tactics.contains(tactic)) tactics.add(tactic);
    }

    public List<String> getRecommendedActions() { return recommendedActions; }
    public void addRecommendedAction(String action) {
        if (!recommendedActions.contains(action)) recommendedActions.add(action);
    }

    public String getImpersonatedBrand() { return impersonatedBrand; }
    public void setImpersonatedBrand(String brand) { this.impersonatedBrand = brand; }

    public String getScamType() { return scamType; }
    public void setScamType(String scamType) { this.scamType = scamType; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    public String getExplanationHi() { return explanationHi; }
    public void setExplanationHi(String explanationHi) { this.explanationHi = explanationHi; }

    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }

    /**
     * Natural ordering: higher risk score first (descending)
     */
    @Override
    public int compareTo(AnalysisResult other) {
        return Integer.compare(other.riskScore, this.riskScore);
    }

    /**
     * Comparator to sort findings by score descending (Lectures 23-25)
     */
    public void sortFindingsBySeverity() {
        findings.sort(Comparator.comparingInt(Finding::getScore).reversed());
    }
}
