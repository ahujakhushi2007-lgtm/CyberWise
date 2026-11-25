package com.cyberwise.test;

import com.cyberwise.model.VerdictConstants;

import java.util.ArrayList;

/**
 * Defines curated Unit 1 & Unit 2 scam-detection test cases across URLs, SMS, and Emails.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A & Unit 2B):</b>
 * Test Cases, {@code ArrayList}, {@code static} factory builder.</p>
 */
public final class CyberWiseTestSuite {

    private CyberWiseTestSuite() {
    }

    public static ArrayList<TestCase> buildScanTestCases() {
        ArrayList<TestCase> cases = new ArrayList<TestCase>();

        cases.add(new TestCase(
                "Phishing: SBI KYC .xyz lookalike URL",
                "LINK",
                "http://sbi-kyc-update.xyz/login",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Phishing: Raw IP address URL",
                "LINK",
                "http://192.168.10.25/sbi/verify",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Phishing: '@' symbol redirect trap",
                "LINK",
                "https://sbi.co.in@evil-phish.top/otp",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Phishing: Paytm typosquatting (.in.net)",
                "LINK",
                "http://paytm-support.in.net/refund",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Safe: Official SBI domain",
                "LINK",
                "https://sbi.co.in",
                VerdictConstants.SAFE, 0, 30));

        cases.add(new TestCase(
                "Safe: Official India Post portal",
                "LINK",
                "https://indiapost.gov.in",
                VerdictConstants.SAFE, 0, 30));

        cases.add(new TestCase(
                "SMS: Hinglish SBI KYC + OTP scam",
                "SMS",
                "Dear user, aapka account band ho jayega within 24 hours. Turant KYC update karein aur OTP share kijiye at http://sbi-kyc.xyz",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "SMS: Digital Arrest (CBI / Skype)",
                "SMS",
                "CBI Crime Branch: Non-bailable arrest warrant issued. Join Skype interrogation immediately or face digital arrest.",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "SMS: Courier customs parcel scam",
                "SMS",
                "FedEx Alert: Your parcel held at Mumbai Airport customs contains drugs. Pay customs clearance fee immediately.",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "SMS: UPI Cashback PIN trap",
                "SMS",
                "You won PhonePe reward Rs 5000! Enter UPI PIN to claim cashback today itself.",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Email: Spoofed HDFC sender + OTP lure",
                "EMAIL",
                "From: alert@hdfc-kyc.top\nDear Customer, your password has expired. Share OTP immediately.",
                VerdictConstants.DANGEROUS, 66, 100));

        cases.add(new TestCase(
                "Safe: Legitimate bank debit SMS",
                "SMS",
                "SBI: Rs 250.00 debited from A/c XX1234 on 25-Nov-26 via UPI. Visit https://sbi.co.in for details.",
                VerdictConstants.SAFE, 0, 30));

        return cases;
    }
}
