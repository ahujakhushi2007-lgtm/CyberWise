package com.cyberwise.model;

/**
 * Represents a single explainable red flag triggered during a scan.
 * Implements {@code Comparable<RedFlag>} to allow natural descending sorting by weight.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2B):</b>
 * Encapsulation, Overloaded Constructors, Constructor Chaining ({@code this(...)}),
 * Method Overriding ({@code compareTo}, {@code toString}), String Formatting.</p>
 */
public class RedFlag implements Comparable<RedFlag> {

    private final String ruleId;
    private final String ruleName;
    private final String category;
    private final String severity;
    private final int weight;
    private final String matchedText;
    private final int startIndex;
    private final int endIndex;
    private final String explanation;

    /**
     * Full constructor specifying exact character offsets for terminal highlighting.
     */
    public RedFlag(String ruleId, String ruleName, String category, String severity,
                   int weight, String matchedText, int startIndex, int endIndex, String explanation) {
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.category = category;
        this.severity = severity;
        this.weight = weight;
        this.matchedText = matchedText;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
        this.explanation = explanation;
    }

    /**
     * Overloaded constructor for structural findings without a substring span.
     */
    public RedFlag(String ruleId, String ruleName, String category, String severity,
                   int weight, String matchedText, String explanation) {
        this(ruleId, ruleName, category, severity, weight, matchedText, -1, -1, explanation);
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public String getRuleName() {
        return this.ruleName;
    }

    public String getCategory() {
        return this.category;
    }

    public String getSeverity() {
        return this.severity;
    }

    public int getWeight() {
        return this.weight;
    }

    public String getMatchedText() {
        return this.matchedText;
    }

    public int getStartIndex() {
        return this.startIndex;
    }

    public int getEndIndex() {
        return this.endIndex;
    }

    public String getExplanation() {
        return this.explanation;
    }

    @Override
    public int compareTo(RedFlag other) {
        // Descending order by weight, then severity rank
        int weightCmp = Integer.compare(other.weight, this.weight);
        if (weightCmp != 0) {
            return weightCmp;
        }
        return Integer.compare(Severity.rank(other.severity), Severity.rank(this.severity));
    }

    @Override
    public String toString() {
        return String.format("[%s | +%d pts] %s (%s) -> %s",
                this.severity, this.weight, this.ruleName, this.matchedText, this.explanation);
    }
}
