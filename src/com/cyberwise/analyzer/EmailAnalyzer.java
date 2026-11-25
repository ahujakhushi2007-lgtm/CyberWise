package com.cyberwise.analyzer;

import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScanResult;
import com.cyberwise.model.Severity;

/**
 * Analyzes raw email content (headers + body) by extending {@code SmsTextAnalyzer}
 * and adding email-specific spoofing and phishing checks.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 1B):</b>
 * Multilevel Inheritance ({@code AbstractThreatAnalyzer -> SmsTextAnalyzer -> EmailAnalyzer}),
 * Method Overriding with {@code super.performAnalysis(...)}, String Searching & Manipulation.</p>
 */
public class EmailAnalyzer extends SmsTextAnalyzer {

    private static final String[] EMAIL_PHISH_SIGNALS = {
        "dear customer", "dear valued customer", "undisclosed-recipients",
        "verify your mailbox", "password has expired", "attached invoice",
        "download attachment", "click below to verify"
    };

    public EmailAnalyzer() {
        super("EmailAnalyzer", "EMAIL");
    }

    @Override
    protected void performAnalysis(String input, ScanResult result) {
        // Reuse SMS/text rule matching and embedded URL checks via super
        super.performAnalysis(input, result);

        String lower = input.toLowerCase();

        // Check generic email phishing greetings / attachment lures
        for (int i = 0; i < EMAIL_PHISH_SIGNALS.length; i++) {
            String signal = EMAIL_PHISH_SIGNALS[i];
            int idx = lower.indexOf(signal);
            if (idx >= 0) {
                addDeduplicatedFlag(result, new RedFlag(
                        "EMAIL_PHISH_LURE",
                        "Generic Email Phishing Lure",
                        ScamCategory.PHISHING,
                        Severity.MEDIUM,
                        20,
                        input.substring(idx, idx + signal.length()),
                        idx,
                        idx + signal.length(),
                        "Mass phishing emails commonly use generic greetings ('" + signal + "') or urgent verification lures."));
                break;
            }
        }

        // Check From: header against Reply-To: mismatch or free/suspicious sender domains
        checkSenderHeaders(input, lower, result);
    }

    private void checkSenderHeaders(String raw, String lower, ScanResult result) {
        int fromIdx = lower.indexOf("from:");
        if (fromIdx < 0) {
            return;
        }
        int lineEnd = lower.indexOf('\n', fromIdx);
        String fromLine = (lineEnd >= 0) ? lower.substring(fromIdx, lineEnd) : lower.substring(fromIdx);

        boolean mentionsBank = fromLine.contains("sbi") || fromLine.contains("hdfc")
                || fromLine.contains("icici") || fromLine.contains("paytm");
        boolean usesSuspiciousOrFreeMail = fromLine.contains("@gmail.com")
                || fromLine.contains("@yahoo.com")
                || fromLine.contains(".xyz")
                || fromLine.contains(".top")
                || fromLine.contains(".click");

        if (mentionsBank && usesSuspiciousOrFreeMail) {
            String matched = raw.substring(fromIdx, fromIdx + fromLine.length()).trim();
            addDeduplicatedFlag(result, new RedFlag(
                    "EMAIL_SPOOF_SENDER",
                    "Spoofed Bank Sender Email Address",
                    ScamCategory.PHISHING,
                    Severity.CRITICAL,
                    40,
                    matched,
                    fromIdx,
                    fromIdx + matched.length(),
                    "Sender pretends to be a bank/fintech brand while using an unofficial or free email domain."));
        }
    }
}
