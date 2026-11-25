package com.cyberwise.model;

import java.util.ArrayList;

/**
 * Domain model representing an educational India-first scam awareness guide.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * Classes and Objects, Encapsulation, Constructors, {@code ArrayList}.</p>
 */
public class AwarenessArticle {

    private final String id;
    private final String title;
    private final String category;
    private final String summary;
    private final String howItWorks;
    private final ArrayList<String> warningSigns;
    private final ArrayList<String> safetyTips;
    private final String sampleScam;

    public AwarenessArticle(String id, String title, String category, String summary,
                            String howItWorks, ArrayList<String> warningSigns,
                            ArrayList<String> safetyTips, String sampleScam) {
        this.id = id;
        this.title = title;
        this.category = category;
        this.summary = summary;
        this.howItWorks = howItWorks;
        this.warningSigns = warningSigns;
        this.safetyTips = safetyTips;
        this.sampleScam = sampleScam;
    }

    public String getId() {
        return this.id;
    }

    public String getTitle() {
        return this.title;
    }

    public String getCategory() {
        return this.category;
    }

    public String getSummary() {
        return this.summary;
    }

    public String getHowItWorks() {
        return this.howItWorks;
    }

    public ArrayList<String> getWarningSigns() {
        return this.warningSigns;
    }

    public ArrayList<String> getSafetyTips() {
        return this.safetyTips;
    }

    public String getSampleScam() {
        return this.sampleScam;
    }
}
