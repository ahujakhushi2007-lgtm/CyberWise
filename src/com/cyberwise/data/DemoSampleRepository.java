package com.cyberwise.data;

import java.util.LinkedHashMap;

/**
 * Provides pre-loaded India-first scam and safe samples for quick Demo Mode showcase.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2B):</b>
 * {@code LinkedHashMap}, Multi-dimensional {@code String[][]} sample table,
 * {@code static} data initialization.</p>
 */
public final class DemoSampleRepository {

    public static final String TYPE_LINK = "LINK";
    public static final String TYPE_SMS = "SMS";
    public static final String TYPE_EMAIL = "EMAIL";

    /**
     * 2D String Array storing demo samples: {key, title, scanType, payload}.
     */
    private static final String[][] DEMO_MATRIX = {
        {
            "1",
            "Fake SBI KYC Hinglish SMS Scam",
            TYPE_SMS,
            "URGENT: Dear SBI YONO user, aapka account band ho jayega within 24 hours. Turant KYC update karein aur OTP share kijiye at http://sbi-kyc-update.xyz"
        },
        {
            "2",
            "Digital Arrest (CBI / Narcotics) Threat",
            TYPE_SMS,
            "CBI Crime Branch Final Warning: Non-bailable arrest warrant issued against your Aadhaar for money laundering case. Join Skype interrogation immediately or face digital arrest."
        },
        {
            "3",
            "Courier / Customs Parcel Scam",
            TYPE_SMS,
            "FedEx Alert: Your parcel held at Mumbai Airport customs contains illegal drugs. Pay customs clearance fee immediately at http://bit.ly/customs-clear-99 or police will act."
        },
        {
            "4",
            "Phishing Lookalike Link (Paytm)",
            TYPE_LINK,
            "http://paytm-support.in.net/verify-kyc-refund?user=987654"
        },
        {
            "5",
            "Spoofed Bank Email (Urgent Password Reset)",
            TYPE_EMAIL,
            "From: security@hdfc-kyc-alert.top\nSubject: Last Chance - Account Suspended\nDear Customer, your HDFC netbanking password has expired. Verify immediately with your OTP and CVV at http://hdfc-kyc-alert.top/login"
        },
        {
            "6",
            "Legitimate Official Bank Transaction Alert (Safe)",
            TYPE_SMS,
            "SBI: Rs 500.00 debited from A/c XX4321 on 25-Nov-26 via UPI Ref 6321894021. If not done by you, visit https://sbi.co.in or call official helpline."
        }
    };

    private static final LinkedHashMap<String, String[]> SAMPLES = new LinkedHashMap<String, String[]>();

    static {
        for (int i = 0; i < DEMO_MATRIX.length; i++) {
            SAMPLES.put(DEMO_MATRIX[i][0], DEMO_MATRIX[i]);
        }
    }

    private DemoSampleRepository() {
    }

    public static String[][] getDemoMatrix() {
        return DEMO_MATRIX;
    }

    public static LinkedHashMap<String, String[]> getSamples() {
        return SAMPLES;
    }
}
