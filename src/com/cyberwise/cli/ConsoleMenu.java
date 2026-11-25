package com.cyberwise.cli;

import com.cyberwise.data.AwarenessRepository;
import com.cyberwise.data.DemoSampleRepository;
import com.cyberwise.engine.SyllabusTracker;
import com.cyberwise.engine.TextSimilarityEngine;
import com.cyberwise.exception.AwarenessNotFoundException;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.exception.ScanLimitExceededException;
import com.cyberwise.exception.UnknownMenuOptionException;
import com.cyberwise.model.AwarenessArticle;
import com.cyberwise.model.ScanResult;
import com.cyberwise.service.DebugTracer;
import com.cyberwise.service.InputValidator;
import com.cyberwise.service.ReportFormatter;
import com.cyberwise.service.ScanService;
import com.cyberwise.test.TestRunner;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Scanner;
import java.util.TreeMap;

/**
 * Interactive console menu controller for CyberWise.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1B, Unit 2A, Unit 2B):</b>
 * Integrated Console Coding ({@code Scanner}), {@code try}, {@code catch}, {@code finally},
 * multi-catch blocks, Input Validation, Exception Propagation handling,
 * {@code Iterator} traversal over {@code LinkedList}, {@code LinkedHashMap}, and {@code TreeMap}.</p>
 */
public class ConsoleMenu {

    private final ScanService scanService;
    private final Scanner scanner;

    public ConsoleMenu(ScanService scanService) {
        this.scanService = scanService;
        this.scanner = new Scanner(System.in);
    }

    /**
     * Starts the interactive menu loop and guarantees scanner cleanup in {@code finally}.
     */
    public void start() {
        printBanner();
        boolean running = true;

        try {
            while (running) {
                printMenu();
                System.out.print(AnsiPalette.BOLD + "  Choose an option [0-8]: " + AnsiPalette.RESET);

                if (!this.scanner.hasNextLine()) {
                    break;
                }
                String rawChoice = this.scanner.nextLine();

                try {
                    int choice = InputValidator.parseMenuChoice(rawChoice, 0, 8);
                    running = handleChoice(choice);
                } catch (UnknownMenuOptionException | NumberFormatException e) {
                    System.out.println(AnsiPalette.RED
                            + "  [Input Error] Please enter a valid number between 0 and 8."
                            + AnsiPalette.RESET);
                } catch (CyberWiseException e) {
                    System.out.println(AnsiPalette.RED
                            + "  [" + e.getErrorCode() + "] " + e.getMessage()
                            + AnsiPalette.RESET);
                } catch (ScanLimitExceededException e) {
                    System.out.println(AnsiPalette.RED
                            + "  [Limit Exceeded] " + e.getMessage()
                            + AnsiPalette.RESET);
                }
            }
        } finally {
            this.scanner.close();
            System.out.println(AnsiPalette.CYAN
                    + "\n  Stay alert, verify before paying, and report fraud at https://cybercrime.gov.in (1930)."
                    + AnsiPalette.RESET);
        }
    }

    private boolean handleChoice(int choice) throws CyberWiseException {
        switch (choice) {
            case 1:
                handleLinkScan();
                return true;
            case 2:
                handleMultiLineScan("SMS");
                return true;
            case 3:
                handleMultiLineScan("EMAIL");
                return true;
            case 4:
                handleViewHistoryAndStats();
                return true;
            case 5:
                handleAwarenessLibrary();
                return true;
            case 6:
                runDemoMode();
                return true;
            case 7:
                TestRunner.runAll();
                return true;
            case 8:
                handleDiagnosticsAndSyllabus();
                return true;
            case 0:
                System.out.println(AnsiPalette.GREEN + "  Exiting CyberWise..." + AnsiPalette.RESET);
                return false;
            default:
                throw new UnknownMenuOptionException(String.valueOf(choice));
        }
    }

    private void handleLinkScan() throws CyberWiseException {
        System.out.print("\n  Enter suspicious URL / link to scan: ");
        if (!this.scanner.hasNextLine()) {
            throw new InvalidInputException("No URL provided.", "URL");
        }
        String url = this.scanner.nextLine();
        ScanResult result = this.scanService.runScan("LINK", url);
        System.out.println(ReportFormatter.formatScanReport(result));
    }

    private void handleMultiLineScan(String scanType) throws CyberWiseException {
        System.out.println("\n  Paste the " + scanType + " text below (type END on a new line to finish):");
        StringBuilder buffer = new StringBuilder();
        while (this.scanner.hasNextLine()) {
            String line = this.scanner.nextLine();
            if ("END".equalsIgnoreCase(line.trim())) {
                break;
            }
            if (buffer.length() > 0) {
                buffer.append("\n");
            }
            buffer.append(line);
        }
        ScanResult result = this.scanService.runScan(scanType, buffer.toString());
        System.out.println(ReportFormatter.formatScanReport(result));
    }

    private void handleViewHistoryAndStats() {
        LinkedList<ScanResult> history = this.scanService.getScanHistoryQueue();
        System.out.println("\n" + AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);
        System.out.println(AnsiPalette.BOLD + "  SCAN HISTORY (LinkedList Queue — Most Recent First)" + AnsiPalette.RESET);
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);

        if (history.isEmpty()) {
            System.out.println("  No scans performed yet in this session.");
        } else {
            Iterator<ScanResult> it = history.iterator();
            while (it.hasNext()) {
                ScanResult sr = it.next();
                String color = ReportFormatter.colorForVerdict(sr.getVerdict());
                System.out.printf("  #%02d | %-5s | %s%3d/100 %-10s%s | %s%n",
                        sr.getScanId(), sr.getScanType(), color, sr.getRiskScore(),
                        sr.getVerdict(), AnsiPalette.RESET, sr.getSummary());
            }

            System.out.println("\n" + AnsiPalette.BOLD + "  CATEGORY FREQUENCY (TreeMap — Sorted Alphabetically)" + AnsiPalette.RESET);
            TreeMap<String, Integer> stats = this.scanService.getCategoryFrequencyMap();
            for (Map.Entry<String, Integer> entry : stats.entrySet()) {
                System.out.printf("    %-40s : %d scan(s)%n", entry.getKey(), entry.getValue());
            }
        }
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);
    }

    private void handleAwarenessLibrary() throws AwarenessNotFoundException {
        LinkedHashMap<String, AwarenessArticle> articles = AwarenessRepository.getAllArticles();
        System.out.println("\n" + AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);
        System.out.println(AnsiPalette.BOLD + "  INDIA-FIRST SCAM AWARENESS LIBRARY" + AnsiPalette.RESET);
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);

        for (Map.Entry<String, AwarenessArticle> entry : articles.entrySet()) {
            System.out.printf("  [%s] %s%n", entry.getKey(), entry.getValue().getTitle());
        }

        System.out.print("\n  Enter topic number to read (1-6, or 0 to go back): ");
        if (!this.scanner.hasNextLine()) {
            return;
        }
        String topicId = this.scanner.nextLine().trim();
        if ("0".equals(topicId)) {
            return;
        }
        AwarenessArticle article = AwarenessRepository.getArticleById(topicId);
        System.out.println(ReportFormatter.formatAwarenessArticle(article));
    }

    /**
     * Runs pre-loaded India-first demo cases for quick terminal demonstration.
     */
    public void runDemoMode() {
        System.out.println("\n" + AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);
        System.out.println(AnsiPalette.BOLD + "  CYBERWISE DEMO MODE (Pre-Loaded India Scam & Safe Samples)" + AnsiPalette.RESET);
        System.out.println(AnsiPalette.CYAN
                + "======================================================================"
                + AnsiPalette.RESET);

        String[][] matrix = DemoSampleRepository.getDemoMatrix();
        for (int i = 0; i < matrix.length; i++) {
            String title = matrix[i][1];
            String type = matrix[i][2];
            String payload = matrix[i][3];

            System.out.println("\n" + AnsiPalette.YELLOW + ">>> Demo Case " + (i + 1) + ": " + title + AnsiPalette.RESET);
            try {
                ScanResult result = this.scanService.runScan(type, payload);
                System.out.println(ReportFormatter.formatScanReport(result));
            } catch (CyberWiseException e) {
                System.out.println(AnsiPalette.RED + "  Demo error: " + e.getMessage() + AnsiPalette.RESET);
            }
        }
    }

    private void handleDiagnosticsAndSyllabus() {
        DebugTracer.toggle();
        System.out.println("\n  Debug Trace Mode is now: "
                + (DebugTracer.isDebugEnabled()
                    ? AnsiPalette.GREEN + "ON" + AnsiPalette.RESET
                    : AnsiPalette.YELLOW + "OFF" + AnsiPalette.RESET));
        System.out.println("  " + TextSimilarityEngine.demonstrateStringPoolAndImmutability());
        System.out.println("\n" + ReportFormatter.formatVerdictLegend());

        System.out.println(AnsiPalette.BOLD + "  UNIT 1 & UNIT 2 SYLLABUS TOPIC MAPPING:" + AnsiPalette.RESET);
        LinkedHashMap<String, String> map = SyllabusTracker.getTopicMap();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            System.out.printf("    %-46s -> %s%n", entry.getKey(), entry.getValue());
        }
    }

    private void printBanner() {
        System.out.println(AnsiPalette.CYAN
                + "\n+--------------------------------------------------------------------+");
        System.out.println("|   CYBERWISE — Explainable India-First Scam Detector (Core Java)    |");
        System.out.println("|   Pure Unit 1 & Unit 2 OOP Edition  |  Offline Forensic Engine     |");
        System.out.println("+--------------------------------------------------------------------+"
                + AnsiPalette.RESET);
    }

    private void printMenu() {
        System.out.println("\n" + AnsiPalette.BOLD + "  MAIN MENU:" + AnsiPalette.RESET);
        System.out.println("  1. Scan a Link (URL)");
        System.out.println("  2. Scan SMS / WhatsApp Text (Multi-line)");
        System.out.println("  3. Scan Email Content (Multi-line)");
        System.out.println("  4. View Scan History & Category Statistics");
        System.out.println("  5. Scam Awareness Library (UPI, KYC, Digital Arrest, Courier, Lottery, Jobs)");
        System.out.println("  6. Demo Mode (Run Pre-Loaded Scam & Safe Samples)");
        System.out.println("  7. Run Built-in Unit Test Suite");
        System.out.println("  8. Toggle Debug Mode & View Unit 1/2 Syllabus Mapping");
        System.out.println("  0. Exit");
    }
}
