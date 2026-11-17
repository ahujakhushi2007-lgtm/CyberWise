package com.cyberwise.benchmark;

import com.cyberwise.analyzer.EmailAnalyzer;
import com.cyberwise.analyzer.TextAnalyzer;
import com.cyberwise.analyzer.UrlAnalyzer;
import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Verdict;

import java.util.ArrayList;
import java.util.List;

/**
 * Executes empirical benchmark suite and evaluates performance using Stream API & Lambdas (Lectures 43-46).
 */
public class BenchmarkRunner {

    public static final List<BenchmarkCase> CASES = new ArrayList<>();

    static {
        // --- Malicious URLs ---
        CASES.add(new BenchmarkCase("URL_MAL_01", "URL", "http://onlinesbi.sbi-kyc-verify.top/login", "DANGEROUS", "Subdomain Phishing"));
        CASES.add(new BenchmarkCase("URL_MAL_02", "URL", "http://192.168.1.105/hdfc/netbanking/login.php", "DANGEROUS", "IP Host Phishing"));
        CASES.add(new BenchmarkCase("URL_MAL_03", "URL", "http://xn--gogle-pqa.com/security-check", "DANGEROUS", "Punycode Homograph"));
        CASES.add(new BenchmarkCase("URL_MAL_04", "URL", "http://paytmm-cashback-reward.click/claim", "DANGEROUS", "Typosquatting"));
        CASES.add(new BenchmarkCase("URL_MAL_05", "URL", "http://icicibank.com@attacker-controlled-server.xyz/verify", "DANGEROUS", "UserInfo @ Spoofing"));
        CASES.add(new BenchmarkCase("URL_MAL_06", "URL", "http://secure.login.update.bank.verification.account-sbi.icu", "DANGEROUS", "Excessive Subdomains"));
        CASES.add(new BenchmarkCase("URL_MAL_07", "URL", "http://uidai-aadhaar-download.icu/verify-otp", "DANGEROUS", "Aadhaar Impersonation"));

        // --- Safe URLs ---
        CASES.add(new BenchmarkCase("URL_SAFE_01", "URL", "https://www.onlinesbi.sbi", "SAFE", "Official Bank Portal"));
        CASES.add(new BenchmarkCase("URL_SAFE_02", "URL", "https://netbanking.hdfcbank.com/netbanking", "SAFE", "Official NetBanking"));
        CASES.add(new BenchmarkCase("URL_SAFE_03", "URL", "https://paytm.com", "SAFE", "Official FinTech"));
        CASES.add(new BenchmarkCase("URL_SAFE_04", "URL", "https://uidai.gov.in", "SAFE", "Government Portal"));
        CASES.add(new BenchmarkCase("URL_SAFE_05", "URL", "https://www.amazon.in/gp/cart/view.html", "SAFE", "E-Commerce Official"));
        CASES.add(new BenchmarkCase("URL_SAFE_06", "URL", "https://www.irctc.co.in/nget/train-search", "SAFE", "Official Rail Booking"));

        // --- Malicious Messages ---
        CASES.add(new BenchmarkCase("TXT_MAL_01", "TEXT", "Dear SBI user, your YONO account is suspended today. Update your PAN card immediately at http://sbi-pan-kyc.xyz to avoid permanent deactivation.", "DANGEROUS", "Fake KYC SMS"));
        CASES.add(new BenchmarkCase("TXT_MAL_02", "TEXT", "CBI Crime Branch Notice: A parcel containing narcotics and fake passports was intercepted in your name. Supreme Court has issued digital arrest warrant. Connect to Skype immediately or SWAT team will arrest you.", "DANGEROUS", "Digital Arrest"));
        CASES.add(new BenchmarkCase("TXT_MAL_03", "TEXT", "प्रिय उपभोक्ता, आपकी बिजली आज रात 9:30 बजे काट दी जाएगी क्योंकि पिछले माह का बिल अपडेट नहीं हुआ है। तुरंत 9876543210 पर संपर्क करें।", "DANGEROUS", "Electricity Bill Discom"));
        CASES.add(new BenchmarkCase("TXT_MAL_04", "TEXT", "PhonePe Cashback: You won Rs 4,999 refund. Scan QR code and enter your secret UPI PIN to receive money instantly into bank.", "DANGEROUS", "UPI PIN Scam"));
        CASES.add(new BenchmarkCase("TXT_MAL_05", "TEXT", "Earn Rs 5,000 daily working from home! Just like YouTube videos and rate Google maps for 20 mins. Contact HR manager on Telegram @EarnFastIndia.", "DANGEROUS", "Telegram Job Fraud"));
        CASES.add(new BenchmarkCase("TXT_MAL_06", "TEXT", "KBC 2026: Aapka number 25 Lakh ki lottery jeeta hai! Amitabh Bachchan lucky draw claim karne ke liye processing fee Rs 1,500 jama karein.", "DANGEROUS", "KBC Lottery"));
        CASES.add(new BenchmarkCase("TXT_MAL_07", "TEXT", "Bank alert: Install AnyDesk app immediately to complete your biometric KYC or your account will be frozen within 2 hours.", "DANGEROUS", "Remote Access Tool"));
        CASES.add(new BenchmarkCase("TXT_MAL_08", "TEXT", "FedEx Customs Warning: Your parcel from Mumbai to Taiwan was intercepted with illegal drugs. Contact Narcotics Control Bureau officer on WhatsApp.", "DANGEROUS", "Courier Customs Fraud"));

        // --- Safe Messages ---
        CASES.add(new BenchmarkCase("TXT_SAFE_01", "TEXT", "Dear Customer, INR 1,500.00 debited from your HDFC Bank A/C ending with **4521 on 31-OCT-26 at SWIGGY. Balance: INR 42,310.45. If not you, SMS BLOCK to 567678 or visit https://www.hdfcbank.com.", "SAFE", "Genuine Bank Debit SMS"));
        CASES.add(new BenchmarkCase("TXT_SAFE_02", "TEXT", "Your Swiggy delivery partner Ramesh is on the way with your food order. Track live in your app.", "SAFE", "Food Delivery Update"));
        CASES.add(new BenchmarkCase("TXT_SAFE_03", "TEXT", "IRCTC Train Booking Confirmed: PNR 2419821894, Train 12952 Mumbai Rajdhani, 3A, Coach B2 Berth 24. Happy Journey!", "SAFE", "Railway Ticket SMS"));
        CASES.add(new BenchmarkCase("TXT_SAFE_04", "TEXT", "Hey Rohit, are we still meeting for coffee this Sunday at 5 PM at Starbucks Indiranagar?", "SAFE", "Personal Chat"));
        CASES.add(new BenchmarkCase("TXT_SAFE_05", "TEXT", "Your monthly Jio fiber bill of Rs 470.82 has been generated. Due date is 15 Nov. Pay conveniently on MyJio app or at https://www.jio.com.", "SAFE", "Telecom Bill Notice"));
        CASES.add(new BenchmarkCase("TXT_SAFE_06", "TEXT", "Reminder: Your appointment with Dr. Mehta at Apollo Clinic is scheduled for tomorrow at 10:30 AM. Call 080-22223333 for rescheduling.", "SAFE", "Clinic Appointment"));
        CASES.add(new BenchmarkCase("TXT_SAFE_07", "TEXT", "Hi Mom, I reached the office safely. Will call you during lunch break!", "SAFE", "Family Message"));

        // --- Malicious Emails ---
        CASES.add(new BenchmarkCase("EML_MAL_01", "EMAIL", "Your account access has been revoked. Click here to verify: http://sbi-login.top", "DANGEROUS", "Email Spoofing + Link",
            "From: \"State Bank of India Alert\" <support@free-host.xyz>\nReply-To: phish@attacker-box.ru\nAuthentication-Results: spf=fail; dkim=fail",
            "Urgent: Your NetBanking Account is Suspended"));
        CASES.add(new BenchmarkCase("EML_MAL_02", "EMAIL", "Your card was billed $1,299 for MacBook. Click <a href=\"http://amazon-dispute.click\">https://amazon.com</a> to cancel.", "DANGEROUS", "Anchor Text Mismatch",
            "From: \"Amazon Security Team\" <security@mail-bot.icu>",
            "Order Cancellation Required"));
        CASES.add(new BenchmarkCase("EML_MAL_03", "EMAIL", "Your income tax refund of INR 28,450 is ready. Download attached voucher: Tax_Refund_Voucher.exe", "DANGEROUS", "Dangerous Attachment",
            "From: \"Income Tax Department\" <refund@tax-portal.live>",
            "Tax Refund Approved"));
        CASES.add(new BenchmarkCase("EML_MAL_04", "EMAIL", "We could not renew your monthly Netflix membership. Update credit card at http://netflix-payment-update.xyz/billing", "DANGEROUS", "Subscription Phishing",
            "From: \"Netflix Billing\" <info@streaming-renewals.buzz>",
            "Account Suspension Notice"));

        // --- Safe Emails ---
        CASES.add(new BenchmarkCase("EML_SAFE_01", "EMAIL", "Dear Customer, Please find your e-statement for October 2026 from HDFC Bank Ltd. Visit https://www.hdfcbank.com.", "SAFE", "Genuine Bank E-Statement",
            "From: \"HDFC Bank Alert\" <alerts@hdfcbank.net>\nAuthentication-Results: spf=pass; dkim=pass",
            "Your Monthly E-Statement for Account ending **4521"));
        CASES.add(new BenchmarkCase("EML_SAFE_02", "EMAIL", "Pull request #4 was successfully merged into main. View changes on GitHub at https://github.com.", "SAFE", "GitHub Notification",
            "From: \"GitHub\" <notifications@github.com>\nAuthentication-Results: spf=pass; dkim=pass",
            "[CyberWise] Pull request #4 merged by maintainer"));
        CASES.add(new BenchmarkCase("EML_SAFE_03", "EMAIL", "You have been invited to event: Team Design Review. Meeting link: https://meet.google.com/abc-defg-hij.", "SAFE", "Google Calendar Invite",
            "From: \"Google Calendar\" <calendar-notification@google.com>",
            "Invitation: Team Design Review @ Thu Nov 5, 2026"));
    }

    public static void main(String[] args) {
        runBenchmark();
    }

    public static void runBenchmark() {
        System.out.println("\n\u001B[36m========================================================================\u001B[0m");
        System.out.println("\u001B[1m🛡️  CYBERWISE — JAVA THREAT INTELLIGENCE BENCHMARK (35 CURATED SAMPLES)\u001B[0m");
        System.out.println("\u001B[36m========================================================================\u001B[0m");

        int tp = 0;
        int tn = 0;
        int fp = 0;
        int fn = 0;

        System.out.printf("%-12s | %-6s | %-26s | %-10s | %-10s | %-5s | %-6s\n",
            "ID", "Type", "Category", "Expected", "Predicted", "Score", "Result");
        System.out.println("-----------------------------------------------------------------------------------------");

        for (BenchmarkCase bc : CASES) {
            AnalysisResult res;
            if ("URL".equals(bc.type)) {
                res = UrlAnalyzer.scan(bc.input);
            } else if ("EMAIL".equals(bc.type)) {
                res = EmailAnalyzer.analyze(bc.emailSubject, bc.input, bc.emailHeaders);
            } else {
                res = TextAnalyzer.scan(bc.input);
            }

            boolean isExpectedMal = "DANGEROUS".equals(bc.expectedVerdict) || "SUSPICIOUS".equals(bc.expectedVerdict);
            boolean isPredMal = res.getVerdict() == Verdict.DANGEROUS || res.getVerdict() == Verdict.SUSPICIOUS;

            boolean pass;
            if (isExpectedMal && isPredMal) { tp++; pass = true; }
            else if (!isExpectedMal && !isPredMal) { tn++; pass = true; }
            else if (!isExpectedMal && isPredMal) { fp++; pass = false; }
            else { fn++; pass = false; }

            String statusColor = pass ? "\u001B[32mPASS\u001B[0m" : "\u001B[31mFAIL\u001B[0m";

            System.out.printf("%-12s | %-6s | %-26s | %-10s | %-10s | %-5d | %s\n",
                bc.id, bc.type, bc.category, bc.expectedVerdict, res.getVerdict(), res.getRiskScore(), statusColor);
        }

        System.out.println("-----------------------------------------------------------------------------------------");

        int total = CASES.size();
        double accuracy = ((double) (tp + tn) / total) * 100.0;
        double precision = (tp + fp > 0) ? ((double) tp / (tp + fp)) * 100.0 : 0.0;
        double recall = (tp + fn > 0) ? ((double) tp / (tp + fn)) * 100.0 : 0.0;
        double f1 = (precision + recall > 0) ? (2 * precision * recall) / (precision + recall) : 0.0;

        System.out.println("\n\u001B[1m📊 PERFORMANCE EVALUATION METRICS (Continuous Assessment 3 Benchmark):\u001B[0m");
        System.out.printf("  • Total Samples Evaluated: %d\n", total);
        System.out.printf("  • True Positives (TP):     %d (Malicious threats correctly flagged)\n", tp);
        System.out.printf("  • True Negatives (TN):     %d (Legitimate items verified safe)\n", tn);
        System.out.printf("  • False Positives (FP):    %d (False alarms)\n", fp);
        System.out.printf("  • False Negatives (FN):    %d (Missed threats)\n", fn);
        System.out.println("  -------------------------------------------------------------");
        System.out.printf("  \u001B[32m✔ ACCURACY:   %.2f%%\u001B[0m\n", accuracy);
        System.out.printf("  \u001B[36m✔ PRECISION:  %.2f%%\u001B[0m\n", precision);
        System.out.printf("  \u001B[35m✔ RECALL:     %.2f%%\u001B[0m\n", recall);
        System.out.printf("  \u001B[33m✔ F1 SCORE:   %.2f%%\u001B[0m\n", f1);
        System.out.println("\u001B[36m========================================================================\u001B[0m\n");
    }
}
