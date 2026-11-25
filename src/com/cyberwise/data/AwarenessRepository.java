package com.cyberwise.data;

import com.cyberwise.exception.AwarenessNotFoundException;
import com.cyberwise.model.AwarenessArticle;
import com.cyberwise.model.ScamCategory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;

/**
 * In-memory knowledge base of India-first cyber scam awareness articles.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 2A, Unit 2B):</b>
 * {@code LinkedHashMap} (menu display order), {@code HashMap} (ID lookup),
 * {@code ArrayList}, {@code throws} and {@code throw} with {@code AwarenessNotFoundException}.</p>
 */
public final class AwarenessRepository {

    private static final LinkedHashMap<String, AwarenessArticle> ORDERED_ARTICLES =
            new LinkedHashMap<String, AwarenessArticle>();
    private static final HashMap<String, AwarenessArticle> ARTICLE_INDEX =
            new HashMap<String, AwarenessArticle>();

    static {
        initArticles();
    }

    private AwarenessRepository() {
    }

    private static void initArticles() {
        register("1", "UPI Collect, QR & Cashback Scams", ScamCategory.UPI_SCAM,
                "Fraudsters trick victims into entering their UPI PIN or approving a 'Collect Request' under the pretext of receiving a refund or cashback.",
                "In UPI, you NEVER need to enter your PIN or scan a QR code to RECEIVE money. Scammers send a 'Collect Request' disguised as a reward or ask you to scan a QR code. The moment you enter your UPI PIN, money is debited from your bank account.",
                new String[]{
                    "Caller insists you scan a QR code to receive OLX/refund/cashback money",
                    "Message says 'Enter UPI PIN to claim Rs. 2,000 cashback'",
                    "Collect request notification pops up with 'Pay' button while caller rushes you"
                },
                new String[]{
                    "Remember: UPI PIN is ONLY for SENDING money, never for receiving",
                    "Decline unknown Collect Requests immediately in GPay/PhonePe/Paytm",
                    "Report unauthorized debits immediately at cybercrime.gov.in or dial 1930"
                },
                "\"Congratulations! You won PhonePe Cashback Rs 4,999. Click link & enter UPI PIN to receive in your bank.\"");

        register("2", "Fake Bank KYC & Account Block Scams", ScamCategory.KYC_SCAM,
                "SMS or WhatsApp alerts claiming your SBI/HDFC/ICICI/PAN/SIM KYC is expired and your account will be blocked today.",
                "Attackers send bulk SMS messages with lookalike URLs (e.g., sbi-kyc-update.xyz). Once you open the fake banking page and enter netbanking credentials, debit card details, and OTP, they drain the account.",
                new String[]{
                    "Message comes from a random 10-digit personal mobile number instead of official bank header",
                    "Domain uses .xyz, .top, .click, or misspelled brand names like sbi-kyc-update.xyz",
                    "Hinglish panic phrases like 'Aapka account aaj band ho jayega, turant KYC karein'"
                },
                new String[]{
                    "Always complete KYC inside your official bank branch or official banking app (e.g., YONO SBI)",
                    "Never click links in urgent banking SMS alerts",
                    "Check the exact domain before logging in (official SBI domain ends in sbi.co.in or onlinesbi.sbi)"
                },
                "\"Dear SBI user, your YONO account will be blocked within 24 hours. Turant KYC update karein: http://sbi-kyc-update.xyz\"");

        register("3", "Digital Arrest & Fake Police / CBI Extortion", ScamCategory.DIGITAL_ARREST,
                "Impersonators posing as CBI, Mumbai Police, Narcotics (NCB), Customs, or TRAI officers threaten arrest over a video call.",
                "Scammers claim your Aadhaar/SIM is linked to money laundering or a seized drug parcel. They force you onto a Skype/WhatsApp video call in fake police uniforms, isolate you ('digital arrest'), and demand 'verification transfers' to 'safe RBI accounts'.",
                new String[]{
                    "Automated IVR claiming TRAI will disconnect your mobile number in 2 hours",
                    "Threat of immediate 'non-bailable arrest warrant' unless you join a video call",
                    "Demand to transfer money to 'clear your name' or verify bank balance"
                },
                new String[]{
                    "NO Indian law enforcement agency conducts 'Digital Arrest' or interrogation over Skype/WhatsApp",
                    "Hang up immediately and verify at your nearest police station",
                    "Call 1930 or report on cybercrime.gov.in immediately"
                },
                "\"CBI Crime Branch Notice: Your Aadhaar is linked to money laundering. Join Skype interrogation immediately or face digital arrest.\"");

        register("4", "Courier, FedEx & Customs Parcel Scams", ScamCategory.COURIER_SCAM,
                "Fake messages or calls claiming an international parcel in your name contains illegal items or requires customs duty.",
                "Victims receive an SMS/IVR saying a FedEx/DHL/India Post parcel is held at Mumbai or Delhi airport customs with drugs/passports inside, or needs a small 'redelivery fee' via a phishing link.",
                new String[]{
                    "Claims a parcel you never sent contains narcotics or illegal passports",
                    "Asks for small customs/redelivery fee via non-government URLs",
                    "Threatens police escalation if customs clearance is not paid immediately"
                },
                new String[]{
                    "Track India Post parcels ONLY on indiapost.gov.in",
                    "Do not enter card details for unexpected Rs. 25-50 redelivery fees",
                    "Disconnect immediately if a 'courier executive' transfers your call to 'police'"
                },
                "\"FedEx Alert: Your parcel held at Mumbai Airport customs contains drugs. Pay customs clearance fee or face NCB action.\"");

        register("5", "KBC / WhatsApp Lottery & Prize Scams", ScamCategory.LOTTERY_SCAM,
                "Messages promising Rs. 25 Lakh KBC or festive lucky-draw winnings if you pay a registration or GST fee.",
                "Fraudsters send fake certificates with celebrity photos over WhatsApp, asking for Rs. 5,000-25,000 in 'processing/tax fees' upfront before releasing prize money that never exists.",
                new String[]{
                    "You won a lottery or KBC draw you never participated in",
                    "Asks for upfront 'processing fee', 'TDS', or 'registration fee'",
                    "Uses fake RBI/SBI stamp images on WhatsApp"
                },
                new String[]{
                    "Genuine prizes never require upfront payment via UPI or gift cards",
                    "Block and report the sender on WhatsApp immediately"
                },
                "\"Badhai ho! Aapne KBC 2026 me Rs 25 Lakh ka inaam jeeta hai. Claim karne ke liye processing fee bhejein.\"");

        register("6", "Part-Time Job & Telegram Prepaid Task Scams", ScamCategory.JOB_SCAM,
                "Offers to earn Rs. 3,000-8,000 daily by liking YouTube videos or rating Google Maps places.",
                "Victims are initially paid Rs. 150-300 to build trust, then added to a Telegram group offering 'VIP prepaid tasks' requiring deposits of Rs. 5,000 to Rs. 1,00,000+ that get frozen.",
                new String[]{
                    "Promises huge daily income for 30 minutes of simple liking/rating tasks",
                    "Moves conversation from WhatsApp to Telegram '@HR_Manager' handles",
                    "Requires 'prepaid recharge' or 'merchant task deposit' to unlock earnings"
                },
                new String[]{
                    "Never pay money to earn salary or unlock task commissions",
                    "Stop immediately if a job asks you to deposit funds into unknown accounts"
                },
                "\"Part-time work from home! Like YouTube videos & earn Rs 5000 daily. Contact HR manager on Telegram immediately.\"");
    }

    private static void register(String id, String title, String category, String summary,
                                 String howItWorks, String[] signs, String[] tips, String sampleScam) {
        ArrayList<String> signList = new ArrayList<String>();
        for (int i = 0; i < signs.length; i++) {
            signList.add(signs[i]);
        }
        ArrayList<String> tipList = new ArrayList<String>();
        for (int i = 0; i < tips.length; i++) {
            tipList.add(tips[i]);
        }
        AwarenessArticle article = new AwarenessArticle(
                id, title, category, summary, howItWorks, signList, tipList, sampleScam);
        ORDERED_ARTICLES.put(id, article);
        ARTICLE_INDEX.put(id, article);
    }

    public static LinkedHashMap<String, AwarenessArticle> getAllArticles() {
        return ORDERED_ARTICLES;
    }

    /**
     * Fetches an article by ID or throws a checked {@code AwarenessNotFoundException}.
     */
    public static AwarenessArticle getArticleById(String id) throws AwarenessNotFoundException {
        if (id == null || !ARTICLE_INDEX.containsKey(id.trim())) {
            throw new AwarenessNotFoundException(id == null ? "null" : id.trim());
        }
        return ARTICLE_INDEX.get(id.trim());
    }
}
