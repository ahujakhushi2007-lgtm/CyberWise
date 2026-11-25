package com.cyberwise.data;

import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScamRule;
import com.cyberwise.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashMap;

/**
 * Stores India-first offline scam detection rules organized by category.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * {@code static} initialization, {@code ArrayList}, and {@code LinkedHashMap}
 * (chosen to preserve category insertion order when displaying rule breakdowns).</p>
 */
public final class RuleRepository {

    private static final ArrayList<ScamRule> ALL_RULES = new ArrayList<ScamRule>();
    private static final LinkedHashMap<String, ArrayList<ScamRule>> RULES_BY_CATEGORY =
            new LinkedHashMap<String, ArrayList<ScamRule>>();

    static {
        loadDefaultRules();
    }

    private RuleRepository() {
    }

    private static void loadDefaultRules() {
        addRule("RULE_KYC_01", "Fake KYC / Account Block Threat", ScamCategory.KYC_SCAM,
                Severity.CRITICAL, 35,
                new String[]{
                    "kyc update", "update your kyc", "pan update", "aadhaar update",
                    "account will be blocked", "account has been blocked", "yono account blocked",
                    "account suspended", "card deactivated", "turant kyc", "kyc update karein",
                    "aapka account band ho jayega", "khata block ho jayega", "khata band"
                },
                "Scammers impersonate banks (SBI/HDFC/ICICI) and threaten account closure to force urgent clicks.");

        addRule("RULE_OTP_01", "OTP / PIN / CVV Credential Request", ScamCategory.OTP_THEFT,
                Severity.CRITICAL, 40,
                new String[]{
                    "share otp", "send otp", "otp share kijiye", "otp bataye", "enter upi pin",
                    "upi pin", "atm pin", "cvv", "mpin", "share password", "4-digit pin",
                    "6-digit pin", "paise receive karne ke liye pin", "pin dalein"
                },
                "Legitimate banks, UPI apps, and officials NEVER ask for your OTP, UPI PIN, ATM PIN, or CVV.");

        addRule("RULE_UPI_01", "UPI Collect / Refund / Cashback Trap", ScamCategory.UPI_SCAM,
                Severity.HIGH, 35,
                new String[]{
                    "accept collect request", "upi collect", "scan qr to receive", "scan qr code to get",
                    "claim cashback", "pending cashback", "phonepe reward", "gpay cashback",
                    "refund accept", "receive money by entering pin", "paisa double"
                },
                "Entering a UPI PIN or scanning a QR code ALWAYS sends money OUT of your account, never into it.");

        addRule("RULE_DIG_01", "Digital Arrest / Fake CBI & Police Threat", ScamCategory.DIGITAL_ARREST,
                Severity.CRITICAL, 45,
                new String[]{
                    "digital arrest", "arrest warrant", "non-bailable warrant", "cbi officer",
                    "cbi crime branch", "narcotics control bureau", "ncb", "supreme court notice",
                    "trai disconnection", "sim will be blocked in 2 hours", "money laundering case",
                    "skype interrogation", "video call interrogation", "stay on video call", "digital custody"
                },
                "Indian police, CBI, Customs, and TRAI NEVER conduct 'digital arrests' or interrogations over video calls.");

        addRule("RULE_COU_01", "Fake Courier / Customs Fee Lure", ScamCategory.COURIER_SCAM,
                Severity.HIGH, 35,
                new String[]{
                    "fedex parcel", "fedex alert", "dhl parcel", "customs duty",
                    "customs clearance fee", "package held at customs", "mumbai airport customs",
                    "delhi airport customs", "india post parcel pending", "re-schedule delivery fee"
                },
                "Fraudsters fabricate customs-fee or redelivery emergencies to extract payments or card details.");

        addRule("RULE_COU_02", "Fake Narcotics / Illegal Parcel Coercion", ScamCategory.COURIER_SCAM,
                Severity.CRITICAL, 40,
                new String[]{
                    "parcel seized", "illegal parcel", "contains drugs", "contains illegal drugs",
                    "drugs found in parcel", "narcotics found", "illegal passport"
                },
                "Scammers falsely claim a parcel in your name contains drugs to panic you into a fake police/customs call.");

        addRule("RULE_LOT_01", "Lottery / KBC / Prize Fee Scam", ScamCategory.LOTTERY_SCAM,
                Severity.HIGH, 35,
                new String[]{
                    "kbc winner", "kbc lottery", "25 lakh lottery", "inaam jeeta hai",
                    "inaam jeeta", "lottery winner", "lucky draw winner", "processing fee to claim",
                    "registration fee for prize", "won rs 25 lakh", "amitabh bachchan lottery"
                },
                "Unsolicited lottery or KBC prize claims asking for processing fees or bank details are always scams.");

        addRule("RULE_UTL_01", "Electricity Disconnection 9:30 PM Scam", ScamCategory.UTILITY_SCAM,
                Severity.HIGH, 35,
                new String[]{
                    "electricity will be disconnected", "electricity power will be cut", "9:30 pm",
                    "9.30 pm", "disconnection tonight", "previous month bill not updated",
                    "call electricity officer", "bijli kaat di jayegi", "bijli bill"
                },
                "Power distribution companies do not threaten same-night 9:30 PM disconnection via personal mobile numbers.");

        addRule("RULE_JOB_01", "Telegram Task / Part-Time Job Scam", ScamCategory.JOB_SCAM,
                Severity.HIGH, 30,
                new String[]{
                    "earn daily", "like youtube videos", "rate google maps", "prepaid task",
                    "telegram hr", "work from home 30 mins", "daily income rs", "part time task",
                    "earn rs 3000", "earn rs 5000"
                },
                "Fake online task scams pay small amounts initially and then trap victims into 'prepaid' deposits.");

        addRule("RULE_URG_01", "High-Pressure Urgency & Fear Language", ScamCategory.URGENCY_COERCION,
                Severity.MEDIUM, 20,
                new String[]{
                    "immediately", "within 24 hours", "within 2 hours", "last chance",
                    "final warning", "urgent notice", "act now", "today itself",
                    "turant", "aaj hi", "antim chetavni"
                },
                "Scammers manufacture fake urgency so you panic and act without verifying.");

        addRule("RULE_REM_01", "Remote Screen-Sharing App Trap", ScamCategory.OTP_THEFT,
                Severity.CRITICAL, 40,
                new String[]{
                    "anydesk", "teamviewer", "rustdesk", "quicksupport", "install support app",
                    "screen share app"
                },
                "Installing remote-access apps lets scammers watch your screen and steal banking OTPs and credentials.");
    }

    private static void addRule(String id, String name, String category, String severity,
                                int weight, String[] phrases, String explanation) {
        ArrayList<String> phraseList = new ArrayList<String>();
        for (int i = 0; i < phrases.length; i++) {
            phraseList.add(phrases[i].toLowerCase());
        }
        ScamRule rule = new ScamRule(id, name, category, severity, weight, phraseList, explanation);
        ALL_RULES.add(rule);

        ArrayList<ScamRule> bucket = RULES_BY_CATEGORY.get(category);
        if (bucket == null) {
            bucket = new ArrayList<ScamRule>();
            RULES_BY_CATEGORY.put(category, bucket);
        }
        bucket.add(rule);
    }

    public static ArrayList<ScamRule> getAllRules() {
        return ALL_RULES;
    }

    public static LinkedHashMap<String, ArrayList<ScamRule>> getRulesByCategory() {
        return RULES_BY_CATEGORY;
    }
}
