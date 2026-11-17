package com.cyberwise.analyzer;

import com.cyberwise.data.BrandRegistry;
import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Brand;
import com.cyberwise.model.Finding;
import com.cyberwise.model.Verdict;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailAnalyzer {

    public static AnalysisResult analyze(String subject, String body, String rawHeaders) {
        String combined = (subject == null ? "" : "Subject: " + subject + "\n") + (body == null ? "" : body);
        AnalysisResult result = new AnalysisResult(subject == null ? "Email" : subject, "EMAIL");

        int score = 0;
        Map<String, String> headers = parseHeaders(rawHeaders);

        String from = headers.getOrDefault("from", "");
        String replyTo = headers.getOrDefault("reply-to", "");
        String returnPath = headers.getOrDefault("return-path", "");
        String authResults = headers.getOrDefault("authentication-results", "").toLowerCase();

        String fromEmail = extractEmail(from).toLowerCase();
        String fromDomain = extractDomain(fromEmail);
        String fromName = extractDisplayName(from).toLowerCase();

        String replyToEmail = extractEmail(replyTo).toLowerCase();
        String replyToDomain = extractDomain(replyToEmail);

        // 1. Display Name Spoofing
        if (!fromName.isEmpty() && !fromDomain.isEmpty()) {
            for (Brand b : BrandRegistry.BRANDS) {
                boolean brandInName = false;
                for (String kw : b.getKeywords()) {
                    if (fromName.contains(kw)) {
                        brandInName = true;
                        break;
                    }
                }

                if (brandInName) {
                    boolean legitDomain = false;
                    for (String d : b.getDomains()) {
                        if (fromDomain.equals(d) || fromDomain.endsWith("." + d)) {
                            legitDomain = true;
                            break;
                        }
                    }
                    if (!legitDomain) {
                        score += 45;
                        result.setImpersonatedBrand(b.getName());
                        result.addFinding(new Finding("display_name_spoof", "Display Name Brand Spoofing (" + b.getName() + ")", "CRITICAL", 45,
                            "Sender display name claims to be '" + fromName + "' while actual originating address is '" + fromEmail + "'."));
                        result.addTactic("Display Name Impersonation");
                        break;
                    }
                }
            }
        }

        // 2. From vs Reply-To Mismatch
        if (!replyToDomain.isEmpty() && !fromDomain.isEmpty() && !replyToDomain.equals(fromDomain)) {
            score += 30;
            result.addFinding(new Finding("reply_to_mismatch", "Sender & Reply-To Domain Divergence", "HIGH", 30,
                "Replies are routed to an unrelated external domain (" + replyToDomain + "), differing from display sender (" + fromDomain + ")."));
            result.addTactic("Reply-To Redirection Divergence");
        }

        // 3. SPF / DKIM Authentication Failures
        if (authResults.contains("spf=fail") || authResults.contains("spf=softfail")) {
            score += 30;
            result.addFinding(new Finding("spf_failure", "SPF (Sender Policy Framework) Failed", "CRITICAL", 30,
                "Originating mail server is not authorized in DNS records to send mail on behalf of " + fromDomain + "."));
        }
        if (authResults.contains("dkim=fail")) {
            score += 30;
            result.addFinding(new Finding("dkim_failure", "DKIM Signature Mismatch", "CRITICAL", 30,
                "Email body/headers were altered in transit or cryptographic signature verification failed."));
        }
        if (authResults.contains("spf=pass") && authResults.contains("dkim=pass")) {
            score -= 35;
            result.addFinding(new Finding("auth_pass", "Cryptographic SPF & DKIM Passed", "SAFE", -35,
                "Originating server and digital signatures match authoritative domain records."));
        }

        // 4. HTML Link Anchor vs Href Divergence
        Pattern anchorPattern = Pattern.compile("<a\\s+(?:[^>]*?\\s+)?href=[\"']([^\"']*)[\"'][^>]*>(.*?)</a>", Pattern.CASE_INSENSITIVE);
        Matcher m = anchorPattern.matcher(body == null ? "" : body);
        while (m.find()) {
            String href = m.group(1);
            String anchorText = m.group(2).replaceAll("<[^>]+>", "").trim();
            if (anchorText.startsWith("http://") || anchorText.startsWith("https://") || anchorText.contains(".com") || anchorText.contains(".in")) {
                try {
                    String cleanAnchor = anchorText.startsWith("http") ? anchorText : "http://" + anchorText;
                    String cleanHref = href.startsWith("http") ? href : "http://" + href;
                    String hostA = URI.create(cleanAnchor).getHost();
                    String hostB = URI.create(cleanHref).getHost();
                    if (hostA != null && hostB != null && !hostA.equalsIgnoreCase(hostB)) {
                        score += 45;
                        result.addFinding(new Finding("anchor_text_spoof", "Deceptive Anchor Text vs Destination Mismatch", "CRITICAL", 45,
                            "Anchor text visibly displays '" + hostA + "' while actual link navigates to '" + hostB + "'."));
                        result.addTactic("Visual Hyperlink Deception");
                    }
                } catch (Exception ignored) {}
            }
        }

        // 5. Dangerous Attachment Mentions
        Pattern attachPattern = Pattern.compile("\\b([a-zA-Z0-9_-]+\\.(?:exe|scr|vbs|js|iso|bat|cmd|apk))\\b", Pattern.CASE_INSENSITIVE);
        Matcher attM = attachPattern.matcher(body == null ? "" : body);
        if (attM.find()) {
            score += 45;
            result.addFinding(new Finding("dangerous_attachment", "Dangerous Executable Attachment (" + attM.group(1) + ")", "CRITICAL", 45,
                "Identified executable malware vector attached to email message."));
            result.addTactic("Malicious Payload Delivery");
        }

        // 6. Analyze Body Text
        AnalysisResult textRes = TextAnalyzer.scan(combined);
        for (Finding f : textRes.getFindings()) {
            result.addFinding(f);
        }
        for (String t : textRes.getTactics()) {
            result.addTactic(t);
        }
        if (result.getScamType() == null) {
            result.setScamType(textRes.getScamType());
        }

        int finalScore = Math.min(100, Math.max(0, score + (int) Math.round(textRes.getRiskScore() * 0.6)));
        result.setRiskScore(finalScore);

        if (result.getVerdict() == Verdict.DANGEROUS) {
            result.setExplanation("CRITICAL EMAIL PHISHING: Displays spoofed sender headers, cryptographic failures, or disguised link destinations designed to breach enterprise credentials.");
            result.setExplanationHi("अत्यंत खतरनाक ईमेल फ्रॉड: इसमें भेजने वाले का नाम फर्जी है और सुरक्षा जांचें फेल हैं।");
            result.addRecommendedAction("Do NOT click any links or download attached files.");
            result.addRecommendedAction("Mark message as Phishing/Spam in email client.");
        } else if (result.getVerdict() == Verdict.SUSPICIOUS) {
            result.setExplanation("SUSPICIOUS EMAIL: Email displays inconsistencies in sender domains or routing headers.");
            result.setExplanationHi("संदिग्ध ईमेल: इसके हेडर और भेजने वाले के पते में विसंगतियां हैं।");
            result.addRecommendedAction("Contact sender through verified secondary channels before replying.");
        } else {
            result.setExplanation("VERIFIED AUTHENTIC EMAIL: Cryptographic signatures and sender alignments match legitimate standards.");
            result.setExplanationHi("प्रमाणित सुरक्षित ईमेल: सुरक्षा मानक और हस्ताक्षर वैध हैं।");
            result.addRecommendedAction("Conforms to verified mail security baselines.");
        }

        return result;
    }

    private static Map<String, String> parseHeaders(String raw) {
        Map<String, String> map = new HashMap<>();
        if (raw == null) return map;
        String[] lines = raw.split("\r?\n");
        String currentKey = null;

        for (String line : lines) {
            if ((line.startsWith(" ") || line.startsWith("\t")) && currentKey != null) {
                map.put(currentKey, map.get(currentKey) + " " + line.trim());
            } else {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    currentKey = line.substring(0, colon).toLowerCase().trim();
                    String val = line.substring(colon + 1).trim();
                    map.put(currentKey, val);
                }
            }
        }
        return map;
    }

    private static String extractEmail(String raw) {
        if (raw == null) return "";
        Matcher m = Pattern.compile("<([^>]+)>").matcher(raw);
        if (m.find()) return m.group(1).trim();
        return raw.trim();
    }

    private static String extractDisplayName(String raw) {
        if (raw == null) return "";
        Matcher m = Pattern.compile("\"?([^\"]+)\"?\\s*<").matcher(raw);
        if (m.find()) return m.group(1).trim();
        return "";
    }

    private static String extractDomain(String email) {
        if (email == null || !email.contains("@")) return "";
        return email.substring(email.indexOf('@') + 1).trim();
    }
}

