package com.cyberwise.model;

/**
 * Constants and display titles for India-first scam categories.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 1B):</b>
 * {@code static} fields and methods, String Pool literals, String comparison.</p>
 */
public final class ScamCategory {

    public static final String PHISHING = "PHISHING";
    public static final String KYC_SCAM = "KYC_SCAM";
    public static final String UPI_SCAM = "UPI_SCAM";
    public static final String DIGITAL_ARREST = "DIGITAL_ARREST";
    public static final String COURIER_SCAM = "COURIER_SCAM";
    public static final String LOTTERY_SCAM = "LOTTERY_SCAM";
    public static final String UTILITY_SCAM = "UTILITY_SCAM";
    public static final String JOB_SCAM = "JOB_SCAM";
    public static final String OTP_THEFT = "OTP_THEFT";
    public static final String URGENCY_COERCION = "URGENCY_COERCION";
    public static final String SAFE_GENERAL = "SAFE_GENERAL";

    private ScamCategory() {
    }

    /**
     * Converts an internal category key into a friendly display title.
     *
     * @param category internal category constant
     * @return display name
     */
    public static String toDisplayName(String category) {
        if (PHISHING.equals(category)) return "Phishing / Fake Domain";
        if (KYC_SCAM.equals(category)) return "Fake Bank / KYC Update Scam";
        if (UPI_SCAM.equals(category)) return "UPI Collect / QR / Refund Scam";
        if (DIGITAL_ARREST.equals(category)) return "Digital Arrest / Fake Police & CBI";
        if (COURIER_SCAM.equals(category)) return "Courier / Customs Parcel Scam";
        if (LOTTERY_SCAM.equals(category)) return "Lottery / KBC Prize Scam";
        if (UTILITY_SCAM.equals(category)) return "Electricity / Utility Disconnection";
        if (JOB_SCAM.equals(category)) return "Part-Time Job / Telegram Task Scam";
        if (OTP_THEFT.equals(category)) return "OTP / PIN / Credential Theft";
        if (URGENCY_COERCION.equals(category)) return "Urgency / Fear Tactics";
        return "General / Safe Content";
    }
}
