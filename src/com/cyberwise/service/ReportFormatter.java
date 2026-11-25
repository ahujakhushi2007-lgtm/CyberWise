package com.cyberwise.service;

import com.cyberwise.cli.AnsiPalette;
import com.cyberwise.engine.RiskScoringMatrix;
import com.cyberwise.model.AwarenessArticle;
import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScanResult;
import com.cyberwise.model.VerdictConstants;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.TreeSet;

/**
 * Formats ANSI-colored terminal reports, highlights matched red-flag spans in bold red,
 * and formats awareness articles using {@code StringBuilder} and {@code String.format}.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B & Unit 2B):</b>
 * {@code StringBuilder}, {@code String.format}, String Slicing ({@code substring}),
 * {@code ArrayList}, {@code LinkedHashSet}, {@code TreeSet}.</p>
 */
public final class ReportFormatter {

    private ReportFormatter() {
    }

    /**
     * Builds the full colorized console report for a {@code ScanResult}.
     */
    public static String formatScanReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        String verdictColor = colorForVerdict(result.getVerdict());

        sb.append("\n").append(AnsiPalette.CYAN)
          .append("======================================================================")
          .append(AnsiPalette.RESET).append("\n");
        sb.append(AnsiPalette.BOLD)
          .append(String.format("  CYBERWISE SCAN REPORT  |  Scan #%d  |  Type: %s",
                  result.getScanId(), result.getScanType()))
          .append(AnsiPalette.RESET).append("\n");
        sb.append(AnsiPalette.CYAN)
          .append("======================================================================")
          .append(AnsiPalette.RESET).append("\n");

        // Score Bar & Verdict
        sb.append(String.format("  Risk Score : %s%s%3d / 100%s   %s\n",
                AnsiPalette.BOLD, verdictColor, result.getRiskScore(), AnsiPalette.RESET,
                buildScoreBar(result.getRiskScore(), verdictColor)));
        sb.append(String.format("  Verdict    : %s%s%s%s  (%s)\n",
                AnsiPalette.BOLD, verdictColor, result.getVerdict(), AnsiPalette.RESET,
                VerdictConstants.describe(result.getVerdict())));
        sb.append(String.format("  Category   : %s\n",
                ScamCategory.toDisplayName(result.getPrimaryCategory())));
        sb.append(String.format("  Summary    : %s\n", result.getSummary()));

        // Highlighted original message with matched red flags in RED + BOLD
        sb.append("\n").append(AnsiPalette.BOLD).append("  Analyzed Input (Red Flags Highlighted):")
          .append(AnsiPalette.RESET).append("\n");
        sb.append("  ").append(highlightRedFlags(result.getOriginalInput(), result.getRedFlags())).append("\n");

        // Triggered Rules Breakdown (already sorted by weight descending via RedFlagWeightComparator)
        ArrayList<RedFlag> flags = result.getRedFlags();
        sb.append("\n").append(AnsiPalette.BOLD)
          .append(String.format("  Triggered Red Flags (%d):", flags.size()))
          .append(AnsiPalette.RESET).append("\n");

        if (flags.isEmpty()) {
            sb.append("    ").append(AnsiPalette.GREEN)
              .append("[OK] No red flags triggered by offline rules.")
              .append(AnsiPalette.RESET).append("\n");
        } else {
            for (int i = 0; i < flags.size(); i++) {
                RedFlag flag = flags.get(i);
                String sevColor = colorForSeverity(flag.getSeverity());
                sb.append(String.format("    %d. %s[%s | +%d pts]%s %s%s%s\n",
                        i + 1, sevColor, flag.getSeverity(), flag.getWeight(), AnsiPalette.RESET,
                        AnsiPalette.BOLD, flag.getRuleName(), AnsiPalette.RESET));
                sb.append(String.format("       Matched : %s\"%s\"%s\n",
                        AnsiPalette.BOLD_RED, flag.getMatchedText(), AnsiPalette.RESET));
                sb.append(String.format("       Why     : %s\n", flag.getExplanation()));
            }
        }

        // Unique tokens & categories summary (TreeSet & LinkedHashSet)
        LinkedHashSet<String> cats = result.getTriggeredCategories();
        TreeSet<String> tokens = result.getUniqueMatchedTokens();
        if (!cats.isEmpty()) {
            sb.append("\n  Vectors Detected (LinkedHashSet) : ").append(cats.toString()).append("\n");
        }
        if (!tokens.isEmpty()) {
            sb.append("  Sorted Flag Tokens (TreeSet)     : ").append(tokens.toString()).append("\n");
        }

        // Customized India-first Next Steps
        sb.append("\n").append(AnsiPalette.BOLD).append("  Recommended Next Steps:")
          .append(AnsiPalette.RESET).append("\n");
        ArrayList<String> steps = result.getNextSteps();
        for (int i = 0; i < steps.size(); i++) {
            sb.append(String.format("    -> %s\n", steps.get(i)));
        }

        sb.append(AnsiPalette.CYAN)
          .append("======================================================================")
          .append(AnsiPalette.RESET).append("\n");
        return sb.toString();
    }

    /**
     * Highlights matched substrings inside the original input text in bold red ANSI color.
     */
    public static String highlightRedFlags(String originalInput, ArrayList<RedFlag> flags) {
        if (originalInput == null || flags == null || flags.isEmpty()) {
            return originalInput == null ? "" : originalInput;
        }

        int len = originalInput.length();
        boolean[] mark = new boolean[len];

        for (int i = 0; i < flags.size(); i++) {
            RedFlag f = flags.get(i);
            int start = f.getStartIndex();
            int end = f.getEndIndex();
            if (start >= 0 && end > start && end <= len) {
                for (int k = start; k < end; k++) {
                    mark[k] = true;
                }
            }
        }

        StringBuilder out = new StringBuilder();
        boolean inHighlight = false;
        for (int i = 0; i < len; i++) {
            if (mark[i] && !inHighlight) {
                out.append(AnsiPalette.BOLD_RED);
                inHighlight = true;
            } else if (!mark[i] && inHighlight) {
                out.append(AnsiPalette.RESET);
                inHighlight = false;
            }
            out.append(originalInput.charAt(i));
        }
        if (inHighlight) {
            out.append(AnsiPalette.RESET);
        }
        return out.toString();
    }

    /**
     * Formats an {@code AwarenessArticle} for terminal reading.
     */
    public static String formatAwarenessArticle(AwarenessArticle article) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n").append(AnsiPalette.CYAN)
          .append("----------------------------------------------------------------------")
          .append(AnsiPalette.RESET).append("\n");
        sb.append(AnsiPalette.BOLD).append("  ").append(article.getTitle())
          .append(AnsiPalette.RESET).append("\n");
        sb.append("  Category: ").append(ScamCategory.toDisplayName(article.getCategory())).append("\n");
        sb.append(AnsiPalette.CYAN)
          .append("----------------------------------------------------------------------")
          .append(AnsiPalette.RESET).append("\n");
        sb.append("  Summary:\n    ").append(article.getSummary()).append("\n\n");
        sb.append("  How the Scam Works:\n    ").append(article.getHowItWorks()).append("\n\n");

        sb.append(AnsiPalette.YELLOW).append("  Warning Signs:")
          .append(AnsiPalette.RESET).append("\n");
        ArrayList<String> signs = article.getWarningSigns();
        for (int i = 0; i < signs.size(); i++) {
            sb.append("    * ").append(signs.get(i)).append("\n");
        }

        sb.append("\n").append(AnsiPalette.GREEN).append("  How to Stay Safe:")
          .append(AnsiPalette.RESET).append("\n");
        ArrayList<String> tips = article.getSafetyTips();
        for (int i = 0; i < tips.size(); i++) {
            sb.append("    + ").append(tips.get(i)).append("\n");
        }

        sb.append("\n  Sample Scam Message:\n    ")
          .append(AnsiPalette.RED).append(article.getSampleScam()).append(AnsiPalette.RESET).append("\n");
        sb.append(AnsiPalette.CYAN)
          .append("----------------------------------------------------------------------")
          .append(AnsiPalette.RESET).append("\n");
        return sb.toString();
    }

    /**
     * Formats the 2D Verdict Scoring Legend Table from {@code RiskScoringMatrix}.
     */
    public static String formatVerdictLegend() {
        String[][] bands = RiskScoringMatrix.getVerdictBands();
        StringBuilder sb = new StringBuilder();
        sb.append("  Scoring Legend:\n");
        for (int i = 0; i < bands.length; i++) {
            sb.append(String.format("    %-10s -> %-11s (%s)\n", bands[i][0], bands[i][1], bands[i][2]));
        }
        return sb.toString();
    }

    private static String buildScoreBar(int score, String color) {
        int filled = score / 5; // 20-char bar
        StringBuilder bar = new StringBuilder();
        bar.append("[").append(color);
        for (int i = 0; i < 20; i++) {
            bar.append(i < filled ? '#' : '-');
        }
        bar.append(AnsiPalette.RESET).append("]");
        return bar.toString();
    }

    public static String colorForVerdict(String verdict) {
        if (VerdictConstants.SAFE.equals(verdict)) {
            return AnsiPalette.GREEN;
        }
        if (VerdictConstants.SUSPICIOUS.equals(verdict)) {
            return AnsiPalette.YELLOW;
        }
        return AnsiPalette.RED;
    }

    private static String colorForSeverity(String severity) {
        if ("CRITICAL".equals(severity) || "HIGH".equals(severity)) {
            return AnsiPalette.BOLD_RED;
        }
        if ("MEDIUM".equals(severity)) {
            return AnsiPalette.YELLOW;
        }
        return AnsiPalette.CYAN;
    }
}
