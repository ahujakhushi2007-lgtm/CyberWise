package com.cyberwise.data;

import com.cyberwise.model.BrandProfile;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

/**
 * Central in-memory registry of trusted Indian brands, suspicious TLDs, and URL shorteners.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * {@code static} initializer block, {@code HashMap} for O(1) brand lookup,
 * {@code HashSet} for fast TLD/shortener/domain membership tests, {@code ArrayList}.</p>
 */
public final class BrandRepository {

    private static final HashMap<String, BrandProfile> BRAND_MAP = new HashMap<String, BrandProfile>();
    private static final HashSet<String> SUSPICIOUS_TLDS = new HashSet<String>();
    private static final HashSet<String> URL_SHORTENERS = new HashSet<String>();
    private static final HashSet<String> ALL_OFFICIAL_DOMAINS = new HashSet<String>();

    static {
        initSuspiciousTlds();
        initUrlShorteners();
        initIndianBrands();
    }

    private BrandRepository() {
    }

    private static void initSuspiciousTlds() {
        String[] tlds = {
            ".xyz", ".top", ".click", ".live", ".icu", ".buzz", ".rest",
            ".support", ".work", ".fit", ".online", ".club", ".site", ".cfd",
            ".vip", ".monster", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".in.net"
        };
        for (int i = 0; i < tlds.length; i++) {
            SUSPICIOUS_TLDS.add(tlds[i]);
        }
    }

    private static void initUrlShorteners() {
        String[] shorteners = {
            "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"
        };
        for (int i = 0; i < shorteners.length; i++) {
            URL_SHORTENERS.add(shorteners[i]);
        }
    }

    private static void initIndianBrands() {
        register("sbi", "State Bank of India (SBI)",
                new String[]{"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "bank.sbi"},
                new String[]{"sbi", "onlinesbi", "yono", "yonosbi"},
                new String[]{"sbi-kyc", "sbi-update", "sbi-online", "sbii", "yonosbi-kyc"});

        register("hdfc", "HDFC Bank",
                new String[]{"hdfcbank.com", "hdfc.com", "netbanking.hdfcbank.com"},
                new String[]{"hdfc", "hdfcbank"},
                new String[]{"hdfc-kyc", "hdfc-update", "hdfcbnk", "hdfc-login"});

        register("icici", "ICICI Bank",
                new String[]{"icicibank.com", "icicibank.co.in", "infinity.icicibank.com"},
                new String[]{"icici", "icicibank", "imobile"},
                new String[]{"icici-kyc", "icic-bank", "icicibankk", "icici-secure"});

        register("axis", "Axis Bank",
                new String[]{"axisbank.com", "axisbank.co.in"},
                new String[]{"axis", "axisbank"},
                new String[]{"axis-kyc", "axis-bank", "axisbnk"});

        register("pnb", "Punjab National Bank",
                new String[]{"pnbindia.in", "netpnb.com"},
                new String[]{"pnb", "pnbindia"},
                new String[]{"pnb-kyc", "pnb-online", "pnbkyc"});

        register("paytm", "Paytm",
                new String[]{"paytm.com", "paytmbank.com"},
                new String[]{"paytm", "paytmbank"},
                new String[]{"paytm-support", "paytm-kyc", "paytm-refund", "paytmm"});

        register("phonepe", "PhonePe",
                new String[]{"phonepe.com"},
                new String[]{"phonepe"},
                new String[]{"phonepe-cashback", "phonepe-refund", "phone-pe", "phonepee"});

        register("gpay", "Google Pay",
                new String[]{"pay.google.com", "google.com"},
                new String[]{"gpay", "googlepay"},
                new String[]{"gpay-cashback", "gpay-refund", "g-pay"});

        register("amazon", "Amazon India",
                new String[]{"amazon.in", "amazon.com", "amzn.to"},
                new String[]{"amazon", "amaz0n"},
                new String[]{"amazon-refund", "amazon-gift", "amaz0n", "amazn"});

        register("flipkart", "Flipkart",
                new String[]{"flipkart.com"},
                new String[]{"flipkart"},
                new String[]{"flipkart-offer", "flipkart-prize", "flipkartt"});

        register("indiapost", "India Post",
                new String[]{"indiapost.gov.in", "indiapostgdsonline.gov.in"},
                new String[]{"indiapost", "india-post", "speedpost"},
                new String[]{"india-post", "indiapost-tracking", "indiapost-customs"});

        register("uidai", "UIDAI / Aadhaar",
                new String[]{"uidai.gov.in", "myaadhaar.uidai.gov.in"},
                new String[]{"uidai", "aadhaar", "myaadhaar"},
                new String[]{"aadhaar-update", "uidai-kyc", "aadhar-verify"});

        register("irctc", "IRCTC",
                new String[]{"irctc.co.in"},
                new String[]{"irctc"},
                new String[]{"irctc-refund", "irctc-ticket", "irctcc"});

        register("cybercrime", "National Cyber Crime Portal",
                new String[]{"cybercrime.gov.in"},
                new String[]{"cybercrime"},
                new String[]{"cybercrime-police", "cybercrime-notice"});
    }

    private static void register(String id, String displayName,
                                 String[] domains, String[] keywords, String[] typos) {
        HashSet<String> domainSet = new HashSet<String>();
        for (int i = 0; i < domains.length; i++) {
            String d = domains[i].toLowerCase();
            domainSet.add(d);
            ALL_OFFICIAL_DOMAINS.add(d);
        }
        ArrayList<String> keywordList = new ArrayList<String>();
        for (int i = 0; i < keywords.length; i++) {
            keywordList.add(keywords[i].toLowerCase());
        }
        ArrayList<String> typoList = new ArrayList<String>();
        for (int i = 0; i < typos.length; i++) {
            typoList.add(typos[i].toLowerCase());
        }
        BRAND_MAP.put(id, new BrandProfile(id, displayName, domainSet, keywordList, typoList));
    }

    public static HashMap<String, BrandProfile> getBrandMap() {
        return BRAND_MAP;
    }

    public static HashSet<String> getSuspiciousTlds() {
        return SUSPICIOUS_TLDS;
    }

    public static HashSet<String> getUrlShorteners() {
        return URL_SHORTENERS;
    }

    public static HashSet<String> getAllOfficialDomains() {
        return ALL_OFFICIAL_DOMAINS;
    }

    public static boolean isOfficialDomain(String host) {
        if (host == null) {
            return false;
        }
        String cleanHost = host.toLowerCase().trim();
        if (cleanHost.startsWith("www.")) {
            cleanHost = cleanHost.substring(4);
        }
        if (ALL_OFFICIAL_DOMAINS.contains(cleanHost)) {
            return true;
        }
        for (String official : ALL_OFFICIAL_DOMAINS) {
            if (cleanHost.endsWith("." + official)) {
                return true;
            }
        }
        return false;
    }
}
