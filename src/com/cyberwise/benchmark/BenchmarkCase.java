package com.cyberwise.benchmark;

public class BenchmarkCase {
    public final String id;
    public final String type; // "URL", "TEXT", "EMAIL"
    public final String input;
    public final String expectedVerdict; // "DANGEROUS", "SUSPICIOUS", "SAFE"
    public final String category;

    // Optional email fields
    public final String emailHeaders;
    public final String emailSubject;

    public BenchmarkCase(String id, String type, String input, String expectedVerdict, String category) {
        this(id, type, input, expectedVerdict, category, null, null);
    }

    public BenchmarkCase(String id, String type, String input, String expectedVerdict, String category, String emailHeaders, String emailSubject) {
        this.id = id;
        this.type = type;
        this.input = input;
        this.expectedVerdict = expectedVerdict;
        this.category = category;
        this.emailHeaders = emailHeaders;
        this.emailSubject = emailSubject;
    }
}

