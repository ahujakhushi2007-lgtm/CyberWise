package com.cyberwise.engine;

/**
 * Computes string similarity using a 2D dynamic-programming edit-distance matrix
 * and demonstrates Java String Immutability and String Pool behavior.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B):</b>
 * Multi-dimensional Arrays ({@code int[][]}), String Immutability, String Pool
 * ({@code ==} vs {@code .equals()}), String manipulation ({@code replace}, {@code toLowerCase}).</p>
 */
public final class TextSimilarityEngine {

    private TextSimilarityEngine() {
    }

    /**
     * Computes Levenshtein edit distance between two strings using a 2D {@code int[][]} array.
     *
     * @param source first string
     * @param target second string
     * @return minimum single-character edits needed to transform source into target
     */
    public static int computeEditDistance(String source, String target) {
        String a = (source == null) ? "" : source.toLowerCase();
        String b = (target == null) ? "" : target.toLowerCase();

        int rows = a.length();
        int cols = b.length();
        int[][] dp = new int[rows + 1][cols + 1];

        for (int i = 0; i <= rows; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= cols; j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= rows; i++) {
            for (int j = 1; j <= cols; j++) {
                int substitutionCost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                int deleteCost = dp[i - 1][j] + 1;
                int insertCost = dp[i][j - 1] + 1;
                int replaceCost = dp[i - 1][j - 1] + substitutionCost;

                dp[i][j] = Math.min(Math.min(deleteCost, insertCost), replaceCost);
            }
        }
        return dp[rows][cols];
    }

    /**
     * Normalizes common homoglyph/lookalike substitutions in suspicious domains.
     * Demonstrates String immutability: each {@code replace} call returns a new String object.
     *
     * @param domain raw domain label
     * @return normalized lowercase domain label
     */
    public static String normalizeHomoglyphs(String domain) {
        if (domain == null) {
            return "";
        }
        String step1 = domain.toLowerCase().trim();
        String step2 = step1.replace("rn", "m");
        String step3 = step2.replace("vv", "w");
        String step4 = step3.replace("0", "o");
        String step5 = step4.replace("1", "l");
        String step6 = step5.replace("3", "e");
        return step6.replace("5", "s");
    }

    /**
     * Demonstrates Java String Pool vs heap String allocation and String Immutability.
     * Used in unit tests and debug trace mode.
     *
     * @return formatted diagnostic explanation
     */
    public static String demonstrateStringPoolAndImmutability() {
        String literalA = "cyberwise";
        String literalB = "cyberwise";
        String heapString = new String("cyberwise");

        boolean poolReferenceSame = (literalA == literalB);
        boolean heapReferenceSame = (literalA == heapString);
        boolean contentEqual = literalA.equals(heapString);

        String original = "sbi";
        original.concat("-kyc"); // Return value ignored: original stays unchanged due to immutability
        boolean immutableVerified = "sbi".equals(original);

        return String.format(
                "StringPool(==): %s | Heap(==): %s | .equals(): %s | ImmutabilityVerified: %s",
                poolReferenceSame, heapReferenceSame, contentEqual, immutableVerified);
    }
}
