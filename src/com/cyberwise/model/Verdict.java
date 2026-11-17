package com.cyberwise.model;

public enum Verdict {
    SAFE,
    SUSPICIOUS,
    DANGEROUS;

    public String getAnsiColor() {
        switch (this) {
            case SAFE:
                return "\u001B[32m"; // Green
            case SUSPICIOUS:
                return "\u001B[33m"; // Yellow / Amber
            case DANGEROUS:
                return "\u001B[31m"; // Red
            default:
                return "\u001B[0m";
        }
    }
}

