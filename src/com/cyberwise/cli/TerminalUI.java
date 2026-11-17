package com.cyberwise.cli;

import com.cyberwise.analyzer.EmailAnalyzer;
import com.cyberwise.analyzer.TextAnalyzer;
import com.cyberwise.analyzer.UrlAnalyzer;
import com.cyberwise.benchmark.BenchmarkRunner;
import com.cyberwise.concurrency.ConcurrentBatchScanner;
import com.cyberwise.concurrency.RadarProgressAnimator;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Finding;
import com.cyberwise.model.Verdict;
import com.cyberwise.storage.FileReportManager;

import java.util.*;

/**
 * Interactive Terminal Console Interface (Lectures 13-15).
 * Features input validation, ANSI color formatting, and ASCII risk gauges.
 */
public class TerminalUI {

    private static final Scanner scanner = new Scanner(System.in);
    private static final List<AnalysisResult> sessionHistory = new ArrayList<>();

    // ANSI Colors
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RED = "\u001B[31m";
    private static final String PURPLE = "\u001B[35m";
    private static final String GRAY = "\u001B[90m";

    public static void start() {
        printBanner();

        boolean keepRunning = true;
        while (keepRunning) {
            printMenu();
            System.out.print(CYAN + BOLD + "Select an option [1-9]: " + RESET);
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    handleUrlScan();
                    break;
                case "2":
                    handleMessageScan();
                    break;
                case "3":
                    handleEmailScan();
                    break;
                case "4":
                    handleSampleDemo();
                    break;
                case "5":
                    handleBatchScan();
                    break;
                case "6":
                    BenchmarkRunner.runBenchmark();
                    break;
                case "7":
                    handleHistoryAndExport();
                    break;
                case "8":
                    handleScamLibrary();
                    break;
                case "9":
                    System.out.println("\n" + GREEN + "Thank you for using CyberWise. Stay cyber safe! 🛡️" + RESET);
                    keepRunning = false;
                    break;
                default:
                    System.out.println(RED + "Invalid option. Please enter a number between 1 and 9." + RESET);
            }
        }
    }

    private static void printBanner() {
        System.out.println(CYAN + BOLD + "================================================================================" + RESET);
        System.out.println(CYAN + BOLD + "   ______      __             _       ___           " + RESET);
        System.out.println(CYAN + BOLD + "  / ____/_  __/ /_  ___  ____| |     / (_)_______   " + RESET);
        System.out.println(CYAN + BOLD + " / /   / / / / __ \\/ _ \\/ ___/ | /| / / / ___/ _ \\  " + RESET);
        System.out.println(CYAN + BOLD + "/ /___/ /_/ / /_/ /  __/ /   | |/ |/ / (__  )  __/  " + RESET);
        System.out.println(CYAN + BOLD + "\\____/\\__, /_.___/\\___/_/    |__/|__/_/____/\\___/   " + RESET);
        System.out.println(CYAN + BOLD + "     /____/                                         " + RESET);
        System.out.println(CYAN + BOLD + "================================================================================" + RESET);
        System.out.println(BOLD + "🛡️  India-First Cyber Threat Intelligence & Phishing Defense Engine (Java Core)" + RESET);
        System.out.println(GRAY + "Continuous Assessment 3 Project Milestone • Pure Java 21 • Zero External Dependencies" + RESET);
        System.out.println(CYAN + "================================================================================\n" + RESET);
    }

    private static void printMenu() {
        System.out.println(BOLD + "\n[ MAIN MENU ]" + RESET);
        System.out.println("  1. 🔗 Scan URL / Suspicious Link");
        System.out.println("  2. 💬 Scan SMS / WhatsApp Message (English, Hinglish, Hindi)");
        System.out.println("  3. ✉️  Scan Raw Email & Authentication Headers (SPF/DKIM)");
        System.out.println("  4. ⚡ Run 8 Realistic Sample Threat Scenarios (Demo Mode)");
        System.out.println("  5. 🧵 Multi-Threaded Batch URL Scanner (Lectures 26-31)");
        System.out.println("  6. 📊 Run 35-Case Benchmark Evaluation (Stream API & Lambdas)");
        System.out.println("  7. 📁 View / Export Scan History (CSV & File I/O)");
        System.out.println("  8. 📚 India Threat Knowledge Base (Digital Arrest, UPI, Discom)");
        System.out.println("  9. 🚪 Exit");
        System.out.println();
    }

    private static void handleUrlScan() {
        System.out.print(CYAN + "Enter URL to scan: " + RESET);
        String url = scanner.nextLine().trim();

        UrlAnalyzer analyzer = new UrlAnalyzer();
        try {
            // Demonstrates custom exception handling (Lectures 10-12)
            RadarProgressAnimator animator = RadarProgressAnimator.startAnimation("Inspecting URL structure & brand databases");
            Thread.sleep(400);
            animator.stop();

            AnalysisResult result = analyzer.analyze(url);
            displayResult(result);
            recordResult(result);
        } catch (InvalidInputException e) {
            System.out.println(RED + "[Validation Error in " + e.getInputField() + "]: " + e.getMessage() + RESET);
        } catch (Exception e) {
            System.out.println(RED + "Scan Error: " + e.getMessage() + RESET);
        }
    }

    private static void handleMessageScan() {
        System.out.println(CYAN + "Enter message / SMS text (press ENTER twice or type END on a new line when finished):" + RESET);
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = scanner.nextLine();
            if (line.equalsIgnoreCase("END") || (line.isEmpty() && sb.length() > 0)) {
                break;
            }
            sb.append(line).append("\n");
        }

        String text = sb.toString().trim();
        TextAnalyzer analyzer = new TextAnalyzer();
        try {
            RadarProgressAnimator animator = RadarProgressAnimator.startAnimation("Analyzing coercion cues, UPI traps & Hinglish phrases");
            Thread.sleep(450);
            animator.stop();

            AnalysisResult result = analyzer.analyze(text);
            displayResult(result);
            recordResult(result);
        } catch (InvalidInputException e) {
            System.out.println(RED + "[Validation Error in " + e.getInputField() + "]: " + e.getMessage() + RESET);
        } catch (Exception e) {
            System.out.println(RED + "Scan Error: " + e.getMessage() + RESET);
        }
    }

    private static void handleEmailScan() {
        System.out.print(CYAN + "Enter Email Subject: " + RESET);
        String subject = scanner.nextLine().trim();

        System.out.print(CYAN + "Enter Email From Address (e.g. \"HDFC Alert\" <alerts@cheaphost.xyz>): " + RESET);
        String from = scanner.nextLine().trim();

        System.out.print(CYAN + "Enter Email Authentication-Results (e.g. spf=fail; dkim=fail, or leave blank): " + RESET);
        String auth = scanner.nextLine().trim();

        System.out.println(CYAN + "Enter Email Body text:" + RESET);
        String body = scanner.nextLine().trim();

        String headers = "From: " + from + "\nAuthentication-Results: " + auth;

        RadarProgressAnimator animator = RadarProgressAnimator.startAnimation("Parsing RFC 822 headers & cryptographic alignments");
        try { Thread.sleep(400); } catch (InterruptedException ignored) {}
        animator.stop();

        AnalysisResult result = EmailAnalyzer.analyze(subject, body, headers);
        displayResult(result);
        recordResult(result);
    }

    private static void handleSampleDemo() {
        System.out.println(BOLD + "\n[ ⚡ REALISTIC DEMO SCENARIOS ]" + RESET);
        System.out.println("  1. Fake SBI YONO KYC Suspension SMS (Hinglish/English)");
        System.out.println("  2. Digital Arrest Supreme Court Extortion WhatsApp (CBI Notice)");
        System.out.println("  3. 9:30 PM Electricity Disconnection Notice (Devanagari Hindi)");
        System.out.println("  4. PhonePe ₹4,999 Cashback Refund UPI PIN Trap");
        System.out.println("  5. Spoofed Amazon Order Invoice Email (SPF/DKIM Failed)");
        System.out.println("  6. Part-Time YouTube Like & Earn ₹5000/day Telegram Job");
        System.out.println("  7. KBC 25 Lakh Amitabh Bachchan Lucky Draw WhatsApp");
        System.out.println("  8. Legitimate HDFC Bank Debit SMS (Verified Safe)");
        System.out.print(CYAN + "\nSelect demo scenario [1-8]: " + RESET);

        String sel = scanner.nextLine().trim();
        switch (sel) {
            case "1":
                displayResult(TextAnalyzer.scan("Dear SBI User, your YONO NetBanking account has been suspended today due to pending KYC verification. Update PAN Card within 24 hours at http://onlinesbi-kyc-verify.top/login. - State Bank of India"));
                break;
            case "2":
                displayResult(TextAnalyzer.scan("CENTRAL BUREAU OF INVESTIGATION (CBI) - CYBER CELL. NOTICE OF DIGITAL ARREST: Consignment intercepted at Mumbai Airport containing 250g MDMA narcotics. Non-bailable arrest warrant issued. Connect to Skype immediately."));
                break;
            case "3":
                displayResult(TextAnalyzer.scan("प्रिय उपभोक्ता, आपकी बिजली आज रात 9:30 बजे काट दी जाएगी क्योंकि पिछले माह का बिल अपडेट नहीं हुआ है। तुरंत 9876543210 पर संपर्क करें। - बिजली विभाग"));
                break;
            case "4":
                displayResult(TextAnalyzer.scan("PhonePe Rewards: You won Rs 4,999 cashback refund! Scan QR code and enter secret UPI PIN to receive money into bank account."));
                break;
            case "5":
                displayResult(EmailAnalyzer.analyze("Unauthorized Order Placed #7029",
                    "Your card was charged $899 for iPhone. Cancel here: <a href=\"http://amazon-cancel.live\">https://amazon.com</a>",
                    "From: \"Amazon Security\" <alert@botnet-node.ru>\nAuthentication-Results: spf=fail; dkim=fail"));
                break;
            case "6":
                displayResult(TextAnalyzer.scan("Earn Rs 3,000 to Rs 8,000 daily from home! Just like YouTube videos and rate Google maps. Contact HR manager on Telegram @EarnDailyOnlineIndia."));
                break;
            case "7":
                displayResult(TextAnalyzer.scan("KBC 2026: Aapka number 25 Lakh ki lottery jeet chuka hai! Prize claim karne ke liye registration fee Rs 1,500 jama karein."));
                break;
            case "8":
                displayResult(TextAnalyzer.scan("Dear Customer, INR 1,500.0 debited from your HDFC Bank A/C ending with **4521 on 31-OCT-26 at SWIGGY. Balance: INR 42,310.45. If not you, SMS BLOCK to 567678 or visit https://www.hdfcbank.com."));
                break;
            default:
                System.out.println(RED + "Invalid scenario choice." + RESET);
        }
    }

    private static void handleBatchScan() {
        System.out.println(CYAN + BOLD + "\n[ 🧵 MULTI-THREADED BATCH SCANNER (Lectures 26-31) ]" + RESET);
        System.out.println("Demonstrates Thread, Runnable, start(), join(), synchronized blocks, and thread priority scheduling.");

        List<String> sampleBatch = Arrays.asList(
            "http://onlinesbi.sbi-kyc-verify.top/login",
            "https://www.onlinesbi.sbi",
            "http://192.168.1.105/hdfc/netbanking/login.php",
            "https://netbanking.hdfcbank.com",
            "http://paytmm-cashback-reward.click/claim",
            "https://paytm.com",
            "http://uidai-aadhaar-download.icu/verify-otp",
            "https://uidai.gov.in",
            "http://icicibank.com@attacker-box.xyz/login",
            "https://www.amazon.in"
        );

        System.out.println("Processing " + sampleBatch.size() + " target URLs concurrently using 4 worker threads...");
        ConcurrentBatchScanner batchScanner = new ConcurrentBatchScanner(sampleBatch, 4);

        long start = System.currentTimeMillis();
        List<AnalysisResult> batchResults = batchScanner.executeBatchScan();
        long duration = System.currentTimeMillis() - start;

        System.out.println(GREEN + "✔ Multithreaded batch scan finished in " + duration + " ms!\n" + RESET);
        System.out.printf("%-4s | %-12s | %-6s | %-42s | %-20s\n", "Rank", "Verdict", "Score", "Target URL", "Processed By");
        System.out.println("--------------------------------------------------------------------------------------------------");

        int rank = 1;
        for (AnalysisResult r : batchResults) {
            String color = r.getVerdict() == Verdict.DANGEROUS ? RED : (r.getVerdict() == Verdict.SUSPICIOUS ? YELLOW : GREEN);
            System.out.printf("%-4d | %s%-12s%s | %-6s | %-42s | %-20s\n",
                rank++, color, r.getVerdict(), RESET, r.getRiskScore() + "/100",
                r.getTarget().length() > 40 ? r.getTarget().substring(0, 39) + "..." : r.getTarget(),
                r.getMode());
            recordResult(r);
        }
    }

    private static void handleHistoryAndExport() {
        System.out.println(BOLD + "\n[ 📁 SCAN AUDIT HISTORY & PERSISTENCE (Lectures 49-54) ]" + RESET);
        List<String[]> records = FileReportManager.loadHistoryFromCsv();
        if (records.isEmpty()) {
            System.out.println(GRAY + "No audit history found in CSV file yet. Run some scans first!" + RESET);
            return;
        }

        System.out.println("Total Records in cyberwise_history.csv: " + records.size());
        System.out.printf("%-24s | %-6s | %-10s | %-6s | %-40s\n", "Date", "Type", "Verdict", "Score", "Target");
        System.out.println("------------------------------------------------------------------------------------------------");

        for (int i = Math.max(0, records.size() - 8); i < records.size(); i++) {
            String[] r = records.get(i);
            if (r.length >= 5) {
                System.out.printf("%-24s | %-6s | %-10s | %-6s | %-40s\n",
                    r[0].length() > 24 ? r[0].substring(0, 24) : r[0],
                    r[1], r[2], r[3],
                    r[4].length() > 38 ? r[4].substring(0, 38) + "..." : r[4]);
            }
        }
    }

    private static void handleScamLibrary() {
        System.out.println(BOLD + "\n[ 📚 INDIA SCAM BLUEPRINT KNOWLEDGE BASE ]" + RESET);
        System.out.println(RED + BOLD + "1. DIGITAL ARREST / CBI VIDEO INTERROGATION:" + RESET);
        System.out.println("   • Scam: Impersonates Police/CBI via Skype video claiming a courier has drugs in your name.");
        System.out.println("   • Truth: Digital Arrest DOES NOT EXIST in Indian law. Courts never hold video arrests.");
        System.out.println("   • Helpline: Immediately hang up and dial 1930.\n");

        System.out.println(YELLOW + BOLD + "2. UPI CASHBACK & REVERSE QR FRAUD:" + RESET);
        System.out.println("   • Scam: Prompts user to enter UPI PIN or scan QR code to 'claim pending ₹4,999 cashback'.");
        System.out.println("   • Golden Rule: UPI PIN is entered ONLY to SEND/DEBIT money, NEVER to receive funds!\n");

        System.out.println(RED + BOLD + "3. 9:30 PM ELECTRICITY DISCONNECTION:" + RESET);
        System.out.println("   • Scam: Urgent SMS threatening power will be severed at 9:30 PM tonight unless a personal number is called.");
        System.out.println("   • Truth: State Discoms never issue 2-hour disconnection deadlines via personal mobile numbers.");
    }

    public static void displayResult(AnalysisResult result) {
        String color = result.getVerdict() == Verdict.DANGEROUS ? RED : (result.getVerdict() == Verdict.SUSPICIOUS ? YELLOW : GREEN);

        System.out.println("\n" + color + "================================================================================" + RESET);
        System.out.println(BOLD + "🔍 PHISHSHIELD AI — FORENSIC THREAT ASSESSMENT REPORT" + RESET);
        System.out.println(color + "================================================================================" + RESET);

        // Visual ASCII Risk Gauge
        int score = result.getRiskScore();
        int filled = score / 5; // 20 characters wide gauge
        StringBuilder gauge = new StringBuilder("[");
        for (int i = 0; i < 20; i++) {
            if (i < filled) gauge.append("█");
            else gauge.append("-");
        }
        gauge.append("]");

        System.out.println("Target:        " + BOLD + result.getTarget() + RESET);
        System.out.println("Verdict:       " + color + BOLD + "[ " + result.getVerdict() + " ]" + RESET);
        System.out.println("Risk Score:    " + color + BOLD + score + " / 100 " + gauge + RESET);
        if (result.getImpersonatedBrand() != null) {
            System.out.println("Target Brand:  " + RED + result.getImpersonatedBrand() + RESET);
        }
        if (result.getScamType() != null) {
            System.out.println("Scam Pattern:  " + PURPLE + result.getScamType() + RESET);
        }
        System.out.println("Engine Mode:   " + GRAY + result.getMode() + RESET);

        System.out.println("\n" + BOLD + "Summary Explanation:" + RESET);
        System.out.println(result.getExplanation());
        if (result.getExplanationHi() != null && !result.getExplanationHi().isEmpty()) {
            System.out.println(GRAY + "हिंदी: " + result.getExplanationHi() + RESET);
        }

        // Findings
        System.out.println("\n" + BOLD + "Forensic Red Flags Detected (" + result.getFindings().size() + "):" + RESET);
        if (result.getFindings().isEmpty()) {
            System.out.println("  " + GREEN + "✔ Zero adverse findings. Conforms to authentic standards." + RESET);
        } else {
            for (Finding f : result.getFindings()) {
                String fColor = "CRITICAL".equalsIgnoreCase(f.getSeverity()) ? RED : ("HIGH".equalsIgnoreCase(f.getSeverity()) ? YELLOW : CYAN);
                System.out.printf("  • %s[%-8s | +%-2d pts]%s %s\n", fColor, f.getSeverity(), f.getScore(), RESET, f.getTitle());
                System.out.println("    " + GRAY + f.getDescription() + RESET);
            }
        }

        // Recommended Actions
        System.out.println("\n" + BOLD + "Recommended Defense Actions:" + RESET);
        for (String a : result.getRecommendedActions()) {
            System.out.println("  [✓] " + a);
        }

        System.out.println("\n" + CYAN + "Emergency Resources: Dial 1930 (National Cybercrime) • Portal: cybercrime.gov.in" + RESET);
        System.out.println(color + "================================================================================\n" + RESET);

        // Prompt to export report to text file
        System.out.print(GRAY + "Export this report to a file? [y/N]: " + RESET);
        String ans = scanner.nextLine().trim();
        if (ans.equalsIgnoreCase("y")) {
            String path = FileReportManager.exportTextReport(result, "threat_report.txt");
            if (path != null) {
                System.out.println(GREEN + "✔ Report successfully exported to: " + path + RESET);
            }
        }
    }

    private static void recordResult(AnalysisResult r) {
        sessionHistory.add(r);
        FileReportManager.saveToCsv(r);
    }
}
