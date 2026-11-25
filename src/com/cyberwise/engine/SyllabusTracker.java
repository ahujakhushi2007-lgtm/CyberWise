package com.cyberwise.engine;

import java.util.LinkedHashMap;

/**
 * Maintains an explicit mapping between every Unit 1 & Unit 2 Java OOP syllabus topic
 * and the exact CyberWise class and method where it is implemented.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * {@code LinkedHashMap} preserving exact syllabus order, {@code static} initialization.</p>
 */
public final class SyllabusTracker {

    private static final LinkedHashMap<String, String> TOPIC_TO_CODE_MAP =
            new LinkedHashMap<String, String>();

    static {
        // Unit 1A
        TOPIC_TO_CODE_MAP.put("Unit 1A: OOP Concepts & Object Modelling",
                "BrandProfile, RedFlag, ScamRule, ScanResult, AwarenessArticle");
        TOPIC_TO_CODE_MAP.put("Unit 1A: Classes, Objects, Methods & Constructors",
                "RedFlag(overloaded constructors), ScanResult(scanId counter), BrandProfile");
        TOPIC_TO_CODE_MAP.put("Unit 1A: 'this' and 'static' Keywords",
                "ScanResult.nextScanId (static), this(...) in RedFlag & AbstractThreatAnalyzer");
        TOPIC_TO_CODE_MAP.put("Unit 1A: Inheritance (Single & Multilevel)",
                "AbstractThreatAnalyzer -> SmsTextAnalyzer -> EmailAnalyzer; CyberWiseException -> InvalidInputException");
        TOPIC_TO_CODE_MAP.put("Unit 1A: Polymorphism (Overloading & Overriding)",
                "Overloading: LinkAnalyzer.analyze(String, boolean), ScanResult.addRedFlag(...); Overriding: performAnalysis()");
        TOPIC_TO_CODE_MAP.put("Unit 1A: Abstraction & Interfaces",
                "ThreatAnalyzer (interface), AbstractThreatAnalyzer (abstract class)");

        // Unit 1B
        TOPIC_TO_CODE_MAP.put("Unit 1B: Multi-dimensional Arrays",
                "TextSimilarityEngine.computeEditDistance() [int[][]], RiskScoringMatrix [int[][] & String[][]], DemoSampleRepository [String[][]]");
        TOPIC_TO_CODE_MAP.put("Unit 1B: String Immutability & String Pool",
                "TextSimilarityEngine.normalizeHomoglyphs() & demonstrateStringPoolAndImmutability()");
        TOPIC_TO_CODE_MAP.put("Unit 1B: String Comparison, Searching & Manipulation",
                "RuleMatcher.findPhraseWithBoundaries(), LinkAnalyzer.performAnalysis() (indexOf, substring, split, equals)");
        TOPIC_TO_CODE_MAP.put("Unit 1B: String Formatting",
                "ReportFormatter.formatScanReport(), TestRunner.runAll() (String.format & printf)");
        TOPIC_TO_CODE_MAP.put("Unit 1B: StringBuilder & StringBuffer",
                "ReportFormatter (StringBuilder for ANSI highlight/report), ScanService/ScanResult (StringBuffer audit log)");
        TOPIC_TO_CODE_MAP.put("Unit 1B: Wrapper Classes",
                "InputValidator.parseMenuChoice() [Integer.parseInt], RuleMatcher [Character.isLetterOrDigit], Severity [Integer.valueOf]");

        // Unit 2A
        TOPIC_TO_CODE_MAP.put("Unit 2A: Checked & Unchecked Exceptions",
                "Checked: CyberWiseException, InvalidInputException; Unchecked: ScanLimitExceededException");
        TOPIC_TO_CODE_MAP.put("Unit 2A: try, catch, finally & multi-catch",
                "ConsoleMenu.start() (try-catch-finally & multi-catch), TestRunner.runAll()");
        TOPIC_TO_CODE_MAP.put("Unit 2A: Exception Propagation, throw & throws",
                "InputValidator -> AbstractThreatAnalyzer -> ScanService -> ConsoleMenu");
        TOPIC_TO_CODE_MAP.put("Unit 2A: Integrated Console Coding & Input Validation",
                "ConsoleMenu, InputValidator.validateNonEmpty(), InputValidator.validateUrl()");
        TOPIC_TO_CODE_MAP.put("Unit 2A: Debugging & Test Cases",
                "DebugTracer.log(), CyberWiseTestSuite, TestRunner (--test / Option 7)");

        // Unit 2B
        TOPIC_TO_CODE_MAP.put("Unit 2B: ArrayList",
                "ScanResult.redFlags, RuleRepository.ALL_RULES, CyberWiseTestSuite.buildScanTestCases()");
        TOPIC_TO_CODE_MAP.put("Unit 2B: LinkedList",
                "ScanService.scanHistoryQueue (recent scan history queue with head/tail operations)");
        TOPIC_TO_CODE_MAP.put("Unit 2B: HashSet, LinkedHashSet & TreeSet",
                "BrandRepository (HashSet TLDs/domains), ScanResult.triggeredCategories (LinkedHashSet), ScanResult.uniqueMatchedTokens (TreeSet)");
        TOPIC_TO_CODE_MAP.put("Unit 2B: HashMap, LinkedHashMap & TreeMap",
                "BrandRepository (HashMap), AwarenessRepository (LinkedHashMap), ScanService.categoryFrequencyMap (TreeMap)");
    }

    private SyllabusTracker() {
    }

    public static LinkedHashMap<String, String> getTopicMap() {
        return TOPIC_TO_CODE_MAP;
    }
}
