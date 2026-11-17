package com.cyberwise.model;

public class Finding {
    private final String id;
    private final String title;
    private final String severity; // "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"
    private final int score;
    private final String description;

    public Finding(String id, String title, String severity, int score, String description) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.score = score;
        this.description = description;
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getSeverity() { return severity; }
    public int getScore() { return score; }
    public String getDescription() { return description; }

    @Override
    public String toString() {
        return "[" + severity + " | +" + score + " pts] " + title + ": " + description;
    }
}

