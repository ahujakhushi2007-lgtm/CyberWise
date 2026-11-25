package com.cyberwise.engine;

import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamRule;

import java.util.ArrayList;

/**
 * Searches input text for scam rule trigger phrases and extracts embedded URLs
 * using core String searching and Character wrapper boundary checks.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B & Unit 2B):</b>
 * String Searching ({@code indexOf}, {@code contains}, {@code substring}, {@code startsWith}),
 * Wrapper Class {@code Character} ({@code Character.isLetterOrDigit}), {@code ArrayList}.</p>
 */
public final class RuleMatcher {

    private RuleMatcher() {
    }

    /**
     * Evaluates a list of {@code ScamRule} objects against raw text and returns matching red flags
     * with exact character indices for inline ANSI highlighting.
     *
     * @param rawText input message or email body
     * @param rules   list of offline rules
     * @return list of triggered RedFlag findings
     */
    public static ArrayList<RedFlag> matchRules(String rawText, ArrayList<ScamRule> rules) {
        ArrayList<RedFlag> flags = new ArrayList<RedFlag>();
        if (rawText == null || rawText.trim().isEmpty()) {
            return flags;
        }

        String lowerText = rawText.toLowerCase();

        for (int r = 0; r < rules.size(); r++) {
            ScamRule rule = rules.get(r);
            ArrayList<String> phrases = rule.getTriggerPhrases();

            for (int p = 0; p < phrases.size(); p++) {
                String phrase = phrases.get(p);
                int idx = findPhraseWithBoundaries(lowerText, phrase);
                if (idx >= 0) {
                    String exactSlice = rawText.substring(idx, idx + phrase.length());
                    RedFlag flag = new RedFlag(
                            rule.getRuleId(),
                            rule.getRuleName(),
                            rule.getCategory(),
                            rule.getSeverity(),
                            rule.getWeight(),
                            exactSlice,
                            idx,
                            idx + phrase.length(),
                            rule.getExplanation()
                    );
                    flags.add(flag);
                    break; // Trigger each rule at most once per scan
                }
            }
        }
        return flags;
    }

    /**
     * Finds a phrase in lowercase text while checking left/right alphanumeric boundaries
     * using {@code Character.isLetterOrDigit}.
     */
    private static int findPhraseWithBoundaries(String lowerText, String phrase) {
        int searchFrom = 0;
        while (searchFrom <= lowerText.length() - phrase.length()) {
            int idx = lowerText.indexOf(phrase, searchFrom);
            if (idx < 0) {
                return -1;
            }
            boolean leftOk = (idx == 0) || !Character.isLetterOrDigit(lowerText.charAt(idx - 1));
            int afterIdx = idx + phrase.length();
            boolean rightOk = (afterIdx >= lowerText.length())
                    || !Character.isLetterOrDigit(lowerText.charAt(afterIdx));

            if (leftOk && rightOk) {
                return idx;
            }
            searchFrom = idx + 1;
        }
        return -1;
    }

    /**
     * Extracts candidate URLs from SMS/email text using String splitting and manipulation.
     *
     * @param text raw message text
     * @return list of unique extracted URLs
     */
    public static ArrayList<String> extractUrls(String text) {
        ArrayList<String> urls = new ArrayList<String>();
        if (text == null || text.trim().isEmpty()) {
            return urls;
        }

        String normalized = text.replace("\n", " ").replace("\r", " ").replace("\t", " ");
        String[] tokens = normalized.split(" ");

        for (int i = 0; i < tokens.length; i++) {
            String token = trimTrailingPunctuation(tokens[i].trim());
            if (token.isEmpty()) {
                continue;
            }
            String lower = token.toLowerCase();
            boolean looksLikeUrl = lower.startsWith("http://")
                    || lower.startsWith("https://")
                    || lower.startsWith("www.")
                    || (lower.contains(".") && !lower.contains("@") && hasCommonDomainEnding(lower));

            if (looksLikeUrl && !urls.contains(token)) {
                urls.add(token);
            }
        }
        return urls;
    }

    private static boolean hasCommonDomainEnding(String lowerToken) {
        String[] endings = {".com", ".in", ".co.in", ".org", ".net", ".xyz", ".top", ".click", ".ly", ".sbi"};
        for (int i = 0; i < endings.length; i++) {
            if (lowerToken.contains(endings[i])) {
                return true;
            }
        }
        return false;
    }

    private static String trimTrailingPunctuation(String token) {
        String result = token;
        while (!result.isEmpty()) {
            char last = result.charAt(result.length() - 1);
            if (last == '.' || last == ',' || last == ';' || last == '!' || last == '?' || last == ')') {
                result = result.substring(0, result.length() - 1);
            } else {
                break;
            }
        }
        return result;
    }
}
