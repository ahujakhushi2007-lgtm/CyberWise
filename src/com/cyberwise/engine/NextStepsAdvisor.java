package com.cyberwise.engine;

import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.VerdictConstants;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * Provides India-first actionable next steps customized to the detected scam category and verdict.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * {@code HashMap} mapping scam categories to {@code ArrayList<String>} advice lists.</p>
 */
public final class NextStepsAdvisor {

    private static final HashMap<String, ArrayList<String>> ADVICE_MAP =
            new HashMap<String, ArrayList<String>>();

    static {
        register(ScamCategory.PHISHING, new String[]{
            "Do NOT click the link or enter netbanking/card credentials on the page.",
            "Verify the official domain manually (e.g., sbi.co.in, hdfcbank.com, indiapost.gov.in).",
            "If you already entered credentials, change your password and block cards immediately.",
            "Report phishing URLs at https://cybercrime.gov.in or call National Helpline 1930."
        });

        register(ScamCategory.KYC_SCAM, new String[]{
            "Never update PAN/Aadhaar/Bank KYC through SMS or WhatsApp links.",
            "Open your official bank app (e.g., YONO SBI) or visit your branch directly.",
            "Never share OTP, ATM PIN, or debit card CVV with anyone claiming to be bank support.",
            "Report fraud attempts immediately on 1930 or https://cybercrime.gov.in."
        });

        register(ScamCategory.UPI_SCAM, new String[]{
            "Decline any unknown UPI Collect Request immediately.",
            "Remember: UPI PIN is ONLY for sending money, NEVER for receiving cashback or refunds.",
            "Block the caller/sender number and report via your UPI app + 1930 helpline."
        });

        register(ScamCategory.DIGITAL_ARREST, new String[]{
            "Disconnect the call immediately — Indian Police, CBI, Customs & TRAI NEVER do 'Digital Arrest'.",
            "Do NOT transfer money to any 'RBI verification' or 'safe custody' account.",
            "Verify independently at your local police station and report on https://cybercrime.gov.in or 1930."
        });

        register(ScamCategory.COURIER_SCAM, new String[]{
            "Do not pay customs or redelivery charges via links in random SMS messages.",
            "Track genuine Speed Post / India Post parcels ONLY at https://indiapost.gov.in.",
            "Report courier impersonation calls at 1930 or https://cybercrime.gov.in."
        });

        register(ScamCategory.LOTTERY_SCAM, new String[]{
            "Never pay 'processing fees' or 'GST' to claim any lottery or KBC prize.",
            "Block the sender on WhatsApp/SMS and report at https://cybercrime.gov.in."
        });

        register(ScamCategory.UTILITY_SCAM, new String[]{
            "Verify electricity dues directly via your official DISCOM app or consumer portal.",
            "Never call personal 10-digit mobile numbers listed in 9:30 PM disconnection threats."
        });

        register(ScamCategory.JOB_SCAM, new String[]{
            "Never pay 'prepaid task deposits' or 'registration fees' for online liking/rating jobs.",
            "Exit Telegram task groups and report fraud accounts at https://cybercrime.gov.in or 1930."
        });

        register(ScamCategory.OTP_THEFT, new String[]{
            "NEVER share OTP, PIN, CVV, or MPIN over call, SMS, or screen-sharing apps.",
            "Uninstall AnyDesk/TeamViewer/QuickSupport immediately if asked by an unknown caller.",
            "Call your bank's official helpline and 1930 immediately if an OTP was leaked."
        });
    }

    private NextStepsAdvisor() {
    }

    private static void register(String category, String[] tips) {
        ArrayList<String> list = new ArrayList<String>();
        for (int i = 0; i < tips.length; i++) {
            list.add(tips[i]);
        }
        ADVICE_MAP.put(category, list);
    }

    /**
     * Returns customized guidance for the detected category and verdict.
     */
    public static ArrayList<String> getAdvice(String category, String verdict) {
        if (VerdictConstants.SAFE.equals(verdict)) {
            ArrayList<String> safeTips = new ArrayList<String>();
            safeTips.add("Message appears low-risk, but still double-check sender identity for financial requests.");
            safeTips.add("Keep your OTP, UPI PIN, and CVV private at all times.");
            safeTips.add("Bookmark https://cybercrime.gov.in and remember helpline 1930 for cyber safety.");
            return safeTips;
        }

        ArrayList<String> specific = ADVICE_MAP.get(category);
        if (specific != null) {
            return new ArrayList<String>(specific);
        }

        ArrayList<String> fallback = new ArrayList<String>();
        fallback.add("Do not click suspicious links, scan QR codes, or share OTP/PIN.");
        fallback.add("Block the sender and verify independently using official apps or websites.");
        fallback.add("Report cyber scams at https://cybercrime.gov.in or call 1930.");
        return fallback;
    }
}
