package com.cyberwise.analyzer;

import com.cyberwise.data.BrandRegistry;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Brand;
import com.cyberwise.model.Finding;
import com.cyberwise.model.Verdict;

import java.net.URI;
import java.util.regex.Pattern;

/**
 * URL analyzer extending BaseAnalyzer (Lectures 1-5, 6-9 Strings & Regex, 10-12 Exceptions).
 */
public class UrlAnalyzer extends BaseAnalyzer<String> {

    private static final Pattern IP_PATTERN = Pattern.compile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    private static final String[] PHISH_KEYWORDS = {
        "login", "signin", "verify", "verification", "update", "kyc", "secure",
        "banking", "account", "password", "refund", "cashback", "pan", "aadhaar", "otp"
    };

    public UrlAnalyzer() {
        super("UrlAnalyzer Engine");
    }

    @Override
    protected void validateInput(String input) throws InvalidInputException {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidInputException("URL string cannot be empty or null.", "URL");
        }
        if (input.length() > 2048) {
            throw new InvalidInputException("URL exceeds maximum safe length of 2048 characters.", "URL");
        }
    }

    @Override
    protected AnalysisResult doAnalyze(String input) {
        return analyzeStatic(input);
    }

    @Override
    public AnalysisResult analyze(String input) throws InvalidInputException {
        return super.analyze(input);
    }

    // Static helper for quick evaluations
    public static AnalysisResult scan(String rawUrl) {
        return analyzeStatic(rawUrl);
    }

    public static int levenshteinDistance(String a, String b) {
        if (a == null || b == null) return 0;
        int lenA = a.length();
        int lenB = b.length();
        int[][] dp = new int[lenA + 1][lenB + 1];

        for (int i = 0; i <= lenA; i++) dp[i][0] = i;
        for (int j = 0; j <= lenB; j++) dp[0][j] = j;

        for (int i = 1; i <= lenA; i++) {
            for (int j = 1; j <= lenB; j++) {
                int cost = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                    dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[lenA][lenB];
    }

    public static String normalizeLookalikes(String str) {
        if (str == null) return "";
        return str.replace("rn", "m")
                  .replace("vv", "w")
                  .replace("0", "o")
                  .replace("1", "l")
                  .replace("3", "e")
                  .replace("5", "s");
    }

    private static AnalysisResult analyzeStatic(String rawUrl) {
        String cleanUrl = (rawUrl == null) ? "" : rawUrl.trim();
        AnalysisResult result = new AnalysisResult(cleanUrl, "URL");

        if (cleanUrl.isEmpty()) {
            result.addFinding(new Finding("empty_url", "Empty URL Input", "LOW", 0, "No URL was provided for analysis."));
            result.setExplanation("Empty URL input provided.");
            return result;
        }

        String urlToParse = cleanUrl;
        if (!urlToParse.startsWith("http://") && !urlToParse.startsWith("https://")) {
            urlToParse = "http://" + urlToParse;
        }

        URI uri;
        try {
            uri = URI.create(urlToParse);
        } catch (Exception e) {
            result.setRiskScore(60);
            result.addFinding(new Finding("malformed_url", "Malformed URL Syntax", "HIGH", 60, "URL syntax could not be resolved by standard parsers."));
            result.setExplanation("Malformed or illegal URL structure.");
            return result;
        }

        String host = (uri.getHost() == null) ? "" : uri.getHost().toLowerCase();
        String path = (uri.getPath() == null) ? "" : uri.getPath().toLowerCase();
        String query = (uri.getQuery() == null) ? "" : uri.getQuery().toLowerCase();

        int score = 0;

        // 1. IP Address Host
        boolean isIp = IP_PATTERN.matcher(host).matches();
        if (isIp) {
            score += 45;
            result.addFinding(new Finding("ip_hostname", "Direct Numerical IP Host", "CRITICAL", 45,
                "URL directs to a raw numerical IP (" + host + ") instead of a registered domain name."));
            result.addTactic("Direct IP Hosting Deception");
        }

        // 2. Punycode
        if (host.startsWith("xn--") || host.contains(".xn--")) {
            score += 40;
            result.addFinding(new Finding("punycode_homograph", "Punycode Homograph Domain", "CRITICAL", 40,
                "Punycode encoding detected (" + host + "), commonly leveraged in visual homoglyph attacks."));
            result.addTactic("Homoglyph Cyrillic/Greek Spoofing");
        }

        // 3. Userinfo @ Redirection
        if (cleanUrl.contains("@")) {
            score += 35;
            result.addFinding(new Finding("at_symbol", "User-Info '@' Redirection Trick", "CRITICAL", 35,
                "URL contains an '@' symbol. Browsers treat characters before '@' as credentials, routing to the host after '@'."));
            result.addTactic("URL Authority Spoofing");
        }

        // 4. Suspicious TLD
        for (String tld : BrandRegistry.SUSPICIOUS_TLDS) {
            if (host.endsWith(tld)) {
                score += 25;
                result.addFinding(new Finding("suspicious_tld", "High-Risk TLD (" + tld + ")", "HIGH", 25,
                    "Top-level domain " + tld + " exhibits high statistical prevalence in automated disposable phishing attacks."));
                break;
            }
        }

        // 5. Shorteners
        for (String shortener : BrandRegistry.SHORTENERS) {
            if (host.equals(shortener) || host.endsWith("." + shortener)) {
                score += 20;
                result.addFinding(new Finding("url_shortener", "URL Shortener Masking", "MEDIUM", 20,
                    "Shortening service disguises the ultimate destination server."));
                result.addTactic("Destination Masking");
                break;
            }
        }

        // 6. Insecure HTTP
        if ("http".equalsIgnoreCase(uri.getScheme()) && !isIp) {
            score += 15;
            result.addFinding(new Finding("insecure_http", "Insecure Protocol (HTTP)", "MEDIUM", 15,
                "Connection does not enforce TLS encryption. Passwords and data are transmitted in plaintext."));
        }

        // 7. Excessive Subdomains
        String[] parts = host.split("\\.");
        if (parts.length >= 4 && !isIp) {
            score += 20;
            result.addFinding(new Finding("excessive_subdomains", "Excessive Subdomain Stacking (" + parts.length + " levels)", "MEDIUM", 20,
                "Domain stacks multiple subdomains to push the genuine registered parent off-screen on mobile devices."));
            result.addTactic("Subdomain Masking");
        }

        // 8. Brand Impersonation & Typosquatting
        for (Brand brand : BrandRegistry.BRANDS) {
            boolean isOfficial = false;
            for (String officialDomain : brand.getDomains()) {
                if (host.equals(officialDomain) || host.endsWith("." + officialDomain)) {
                    isOfficial = true;
                    break;
                }
            }

            if (isOfficial) {
                result.addFinding(new Finding("official_domain", "Verified Official Domain: " + brand.getName(), "SAFE", -40,
                    "Host matches authoritative domain registry records for " + brand.getName() + "."));
                score -= 40;
                break;
            }

            // Check if brand keyword in subdomain when host is different
            boolean brandInSub = false;
            for (String kw : brand.getKeywords()) {
                if (host.contains(kw) && !host.endsWith("." + kw + ".com") && !host.endsWith("." + kw + ".in")) {
                    brandInSub = true;
                    break;
                }
            }

            if (brandInSub) {
                score += 45;
                result.setImpersonatedBrand(brand.getName());
                result.addFinding(new Finding("brand_subdomain_spoof", "Brand Impersonation: " + brand.getName(), "CRITICAL", 45,
                    "Brand keyword appears in host/subdomain while registered under an unrelated third-party domain."));
                result.addTactic("Brand Impersonation (" + brand.getName() + ")");
                break;
            }

            // Typosquatting check
            for (String typo : brand.getTypos()) {
                if (host.contains(typo)) {
                    score += 40;
                    result.setImpersonatedBrand(brand.getName());
                    result.addFinding(new Finding("known_typosquat", "Known Phishing Pattern for " + brand.getName(), "CRITICAL", 40,
                        "Host matches active phishing pattern (" + typo + ") targeting " + brand.getName() + " customers."));
                    result.addTactic("Typosquatting");
                    break;
                }
            }
        }

        // 9. Sensitive Path Keywords
        for (String kw : PHISH_KEYWORDS) {
            if (path.contains(kw) || query.contains(kw)) {
                score += 15;
                result.addFinding(new Finding("phish_path_keyword", "Sensitive Action Keyword: '" + kw + "'", "MEDIUM", 15,
                    "URL endpoint targets credential/account modification endpoints typical of credential harvesters."));
                break;
            }
        }

        result.setRiskScore(score);

        if (result.getVerdict() == Verdict.DANGEROUS) {
            result.setExplanation("CRITICAL THREAT: This URL exhibits severe deceptive characteristics including typosquatting, brand impersonation, or high-risk domain anomalies.");
            result.setExplanationHi("अत्यंत खतरनाक लिंक: यह वेबसाइट किसी प्रतिष्ठित संस्था की नकल करके आपके पासवर्ड या पैसे चुराने के लिए बनाई गई है।");
            result.addRecommendedAction("DO NOT open this link or enter passwords, card details, or UPI PINs.");
            result.addRecommendedAction("Report the malicious domain to CERT-In (incident@cert-in.org.in) and National Cyber Crime Portal (1930).");
        } else if (result.getVerdict() == Verdict.SUSPICIOUS) {
            result.setExplanation("SUSPICIOUS URL: This link contains structural irregularities (e.g. unverified TLD, shorteners, or insecure HTTP) that warrant caution.");
            result.setExplanationHi("संदिग्ध लिंक: यह वेबसाइट पूरी तरह सुरक्षित नहीं लग रही है। इस पर कोई भी संवेदनशील विवरण दर्ज न करें।");
            result.addRecommendedAction("Verify the authentic destination before proceeding.");
        } else {
            result.setExplanation("VERIFIED SAFE: The URL resolves to an authoritative verified domain with standard secure TLS encryption.");
            result.setExplanationHi("सुरक्षित लिंक: यह एक आधिकारिक और सत्यापित डोमेन है। इसमें कोई खतरा नहीं पाया गया।");
            result.addRecommendedAction("Conforms to safe web standards. Maintain general vigilance.");
        }

        result.sortFindingsBySeverity();
        return result;
    }
}
