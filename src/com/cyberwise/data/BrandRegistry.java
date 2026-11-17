package com.cyberwise.data;

import com.cyberwise.model.Brand;
import java.util.*;

public class BrandRegistry {
    public static final List<Brand> BRANDS = new ArrayList<>();
    public static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
        ".xyz", ".top", ".click", ".live", ".icu", ".buzz", ".rest", ".support",
        ".work", ".fit", ".online", ".club", ".site", ".cfd", ".vip", ".monster",
        ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".space", ".bid"
    ));

    public static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList(
        "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "shorturl.at"
    ));

    static {
        // Indian Banking
        register("sbi", "State Bank of India",
            Arrays.asList("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "bank.sbi"),
            Arrays.asList("sbi", "onlinesbi", "yono", "yonosbi"),
            Arrays.asList("sbii", "sbi-online", "sbi-kyc", "sbi-update"));

        register("hdfc", "HDFC Bank",
            Arrays.asList("hdfcbank.com", "hdfc.com", "hdfcbank.net", "netbanking.hdfcbank.com"),
            Arrays.asList("hdfc", "hdfcbank", "netbanking.hdfcbank"),
            Arrays.asList("hdfc-bank", "hdfcbnk", "hdfclogin", "hdfc-update", "hdfc-kyc"));

        register("icici", "ICICI Bank",
            Arrays.asList("icicibank.com", "icicibank.co.in", "infinity.icicibank.com"),
            Arrays.asList("icici", "icicibank", "imobile"),
            Arrays.asList("icic-bank", "icicibankk", "icici-secure", "icici-kyc"));

        register("axis", "Axis Bank",
            Arrays.asList("axisbank.com", "axisbank.co.in"),
            Arrays.asList("axis", "axisbank"),
            Arrays.asList("axis-bank", "axisbnk", "axis-login", "axis-kyc"));

        register("pnb", "Punjab National Bank",
            Arrays.asList("pnbindia.in", "netpnb.com"),
            Arrays.asList("pnb", "pnbindia"),
            Arrays.asList("pnb-bank", "pnb-online", "pnbkyc"));

        // Indian FinTech
        register("paytm", "Paytm",
            Arrays.asList("paytm.com", "paytmbank.com"),
            Arrays.asList("paytm", "paytmbank"),
            Arrays.asList("paytmm", "paytm-cash", "paytm-kyc", "paytm-refund"));

        register("phonepe", "PhonePe",
            Arrays.asList("phonepe.com"),
            Arrays.asList("phonepe"),
            Arrays.asList("phone-pe", "phonepee", "phonepe-cashback", "phonepe-refund", "phonepe-rewards"));

        register("gpay", "Google Pay",
            Arrays.asList("pay.google.com", "google.com"),
            Arrays.asList("gpay", "googlepay"),
            Arrays.asList("g-pay", "gpay-cashback", "gpay-refund"));

        // Indian Government & Authorities
        register("uidai", "Aadhaar / UIDAI",
            Arrays.asList("uidai.gov.in", "myaadhaar.uidai.gov.in"),
            Arrays.asList("uidai", "aadhaar", "myaadhaar"),
            Arrays.asList("uidai-update", "aadhaar-download", "aadhar-verification"));

        register("incometax", "Income Tax Department",
            Arrays.asList("incometax.gov.in", "tin-nsdl.com"),
            Arrays.asList("incometax", "incometaxindia", "efiling"),
            Arrays.asList("incometax-refund", "itr-refund", "tax-refund-claim"));

        register("indiapost", "India Post",
            Arrays.asList("indiapost.gov.in", "indiapostgdsonline.gov.in"),
            Arrays.asList("indiapost", "speedpost"),
            Arrays.asList("india-post", "indiapost-tracking", "indiapost-customs"));

        register("irctc", "IRCTC",
            Arrays.asList("irctc.co.in"),
            Arrays.asList("irctc"),
            Arrays.asList("irctcc", "irctc-ticket", "irctc-refund"));

        register("jio", "Reliance Jio",
            Arrays.asList("jio.com"),
            Arrays.asList("jio", "myjio"),
            Arrays.asList("jio-5g-upgrade", "jio-offer", "myjio-kyc"));

        register("amazon", "Amazon",
            Arrays.asList("amazon.in", "amazon.com", "amzn.to"),
            Arrays.asList("amazon", "prime"),
            Arrays.asList("amaz0n", "amazn", "amazon-order", "amazon-refund"));

        register("netflix", "Netflix",
            Arrays.asList("netflix.com"),
            Arrays.asList("netflix"),
            Arrays.asList("netflx", "netflix-billing", "netflix-renew"));

        register("apple", "Apple",
            Arrays.asList("apple.com", "icloud.com"),
            Arrays.asList("apple", "appleid", "icloud"),
            Arrays.asList("appl", "apple-id-verify"));
    }

    private static void register(String id, String name, List<String> domains, List<String> keywords, List<String> typos) {
        BRANDS.add(new Brand(id, name, domains, keywords, typos));
    }
}

