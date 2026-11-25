package com.cyberwise.model;

import java.util.ArrayList;

/**
 * Domain object representing an offline scam detection rule with keywords, weight, and explanation.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * Object Modelling, Encapsulation, Constructors, {@code ArrayList}.</p>
 */
public class ScamRule {

    private final String ruleId;
    private final String ruleName;
    private final String category;
    private final String severity;
    private final int weight;
    private final ArrayList<String> triggerPhrases;
    private final String explanation;

    public ScamRule(String ruleId, String ruleName, String category, String severity,
                    int weight, ArrayList<String> triggerPhrases, String explanation) {
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.category = category;
        this.severity = severity;
        this.weight = weight;
        this.triggerPhrases = triggerPhrases;
        this.explanation = explanation;
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

    public ArrayList<String> getTriggerPhrases() {
        return this.triggerPhrases;
    }

    public String getExplanation() {
        return this.explanation;
    }
}
