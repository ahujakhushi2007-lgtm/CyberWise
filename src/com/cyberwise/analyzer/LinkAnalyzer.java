package com.cyberwise.analyzer;

import com.cyberwise.data.BrandRepository;
import com.cyberwise.engine.TextSimilarityEngine;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.BrandProfile;
import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScanResult;
import com.cyberwise.model.Severity;
import com.cyberwise.service.DebugTracer;
import com.cyberwise.service.InputValidator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

/**
 * Analyzes URLs for India-first phishing, lookalike domains, typosquatting, suspicious TLDs,
 * IP-based URLs, URL shorteners, {@code @} credential traps, and excessive hyphens/subdomains.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2B):</b>
 * Inheritance ({@code extends AbstractThreatAnalyzer}), Method Overriding ({@code validateInput},
 * {@code performAnalysis}), Method Overloading ({@code analyze(String, boolean)}),
 * String Manipulation ({@code indexOf}, {@code substring}, {@code split}, {@code startsWith}),
 * {@code HashMap}, {@code HashSet}, Wrapper {@code Character.isDigit}.</p>
 */
public class LinkAnalyzer extends AbstractThreatAnalyzer {

    private static final String[] PHISHING_PATH_KEYWORDS = {
        "login", "signin", "verify", "verification", "update", "kyc", "secure",
        "banking", "account", "password", "refund", "cashback", "pan", "aadhaar", "otp"
    };

    public LinkAnalyzer() {
        super("LinkAnalyzer", "LINK");
    }

    /**
     * Method Overloading: optionally applies extra strict penalties on unencrypted HTTP links.
     */
    public ScanResult analyze(String input, boolean strictHttpCheck) throws CyberWiseException {
        ScanResult result = this.analyze(input);
        if (strictHttpCheck && input != null && input.toLowerCase().trim().startsWith("http://")) {
            RedFlag httpFlag = new RedFlag(
                    "URL_PLAIN_HTTP",
                    "Unencrypted HTTP Protocol",
                    ScamCategory.PHISHING,
                    Severity.MEDIUM,
                    15,
                    "http://",
                    0,
                    7,
                    "Uses unencrypted http:// instead of https:// — genuine banks never ask for logins over plain HTTP.");
            addDeduplicatedFlag(result, httpFlag);
            com.cyberwise.engine.RiskScoringMatrix.finalizeScore(result);
        }
        return result;
    }

    @Override
    protected String validateInput(String input) throws InvalidInputException {
        return InputValidator.validateUrl(input);
    }

    @Override
    protected void performAnalysis(String input, ScanResult result) {
        String lower = input.toLowerCase();
        String host = extractHost(lower);
        String pathAndQuery = extractPathAndQuery(lower);

        DebugTracer.log("LinkAnalyzer", "Extracted host='" + host + "', path='" + pathAndQuery + "'");

        // 1. Check '@' symbol deception (e.g., http://sbi.co.in@evil.xyz)
        int atIndex = lower.indexOf('@');
        if (atIndex >= 0) {
            result.addRedFlag(new RedFlag(
                    "URL_AT_SYMBOL",
                    "'@' Symbol Redirection Trap",
                    ScamCategory.PHISHING,
                    Severity.CRITICAL,
                    45,
                    "@",
                    atIndex,
                    atIndex + 1,
                    "URLs containing '@' ignore everything before '@' and take you to the fake site after '@'."));
        }

        // 2. Check raw IPv4 address host
        if (isIpAddress(host)) {
            int ipPos = lower.indexOf(host);
            result.addRedFlag(new RedFlag(
                    "URL_IP_HOST",
                    "Raw IP Address Host",
                    ScamCategory.PHISHING,
                    Severity.CRITICAL,
                    45,
                    host,
                    ipPos,
                    ipPos >= 0 ? ipPos + host.length() : -1,
                    "Legitimate banks and portals use registered domains, never raw numeric IP addresses."));
        }

        // 3. Check official trusted domain whitelist before brand/TLD heuristics
        boolean isOfficial = BrandRepository.isOfficialDomain(host);
        if (isOfficial) {
            DebugTracer.log("LinkAnalyzer", "Host matched official Indian brand whitelist: " + host);
            return;
        }

        // 4. Check URL shorteners
        HashSet<String> shorteners = BrandRepository.getUrlShorteners();
        if (shorteners.contains(host)) {
            int pos = lower.indexOf(host);
            result.addRedFlag(new RedFlag(
                    "URL_SHORTENER",
                    "Hidden Destination (URL Shortener)",
                    ScamCategory.PHISHING,
                    Severity.HIGH,
                    35,
                    host,
                    pos,
                    pos >= 0 ? pos + host.length() : -1,
                    "Shortened URLs (" + host + ") hide the real destination and are heavily used in SMS scams."));
        }

        // 5. Check suspicious TLDs
        HashSet<String> suspiciousTlds = BrandRepository.getSuspiciousTlds();
        for (String tld : suspiciousTlds) {
            if (host.endsWith(tld)) {
                int pos = lower.indexOf(tld);
                result.addRedFlag(new RedFlag(
                        "URL_BAD_TLD",
                        "High-Risk Suspicious TLD (" + tld + ")",
                        ScamCategory.PHISHING,
                        Severity.HIGH,
                        35,
                        tld,
                        pos,
                        pos >= 0 ? pos + tld.length() : -1,
                        "Scammers frequently buy cheap domains ending in '" + tld + "' for fake KYC and phishing sites."));
                break;
            }
        }

        // 6. Check excessive hyphens or subdomains
        checkHostStructure(host, lower, result);

        // 7. Check Indian brand impersonation & lookalike typosquatting via 2D Levenshtein matrix
        checkBrandImpersonation(host, lower, result);

        // 8. Check phishing keywords in URL path/query or host
        checkPhishingKeywords(lower, result);

        // 9. Plain HTTP check if already suspicious or non-official
        if (lower.startsWith("http://")) {
            result.addRedFlag(new RedFlag(
                    "URL_INSECURE_HTTP",
                    "Insecure HTTP Connection",
                    ScamCategory.PHISHING,
                    Severity.LOW,
                    15,
                    "http://",
                    0,
                    7,
                    "Connection is not encrypted with HTTPS; genuine financial portals always enforce HTTPS."));
        }
    }

    private void checkHostStructure(String host, String lowerUrl, ScanResult result) {
        int hyphenCount = 0;
        int dotCount = 0;
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            if (ch == '-') hyphenCount++;
            if (ch == '.') dotCount++;
        }

        if (hyphenCount >= 2) {
            int pos = lowerUrl.indexOf(host);
            result.addRedFlag(new RedFlag(
                    "URL_HYPHENS",
                    "Excessive Hyphens in Domain",
                    ScamCategory.PHISHING,
                    Severity.MEDIUM,
                    25,
                    host,
                    pos,
                    pos >= 0 ? pos + host.length() : -1,
                    "Domains with multiple hyphens (e.g. 'sbi-kyc-update') commonly mimic official Indian portals."));
        }

        if (dotCount >= 3 && !isIpAddress(host)) {
            int pos = lowerUrl.indexOf(host);
            result.addRedFlag(new RedFlag(
                    "URL_SUBDOMAINS",
                    "Excessive Subdomains",
                    ScamCategory.PHISHING,
                    Severity.MEDIUM,
                    20,
                    host,
                    pos,
                    pos >= 0 ? pos + host.length() : -1,
                    "Too many subdomains (" + dotCount + " dots) are used to hide the real root domain."));
        }
    }

    private void checkBrandImpersonation(String host, String lowerUrl, ScanResult result) {
        String normalizedHost = TextSimilarityEngine.normalizeHomoglyphs(host);
        String mainLabel = extractMainDomainLabel(host);
        String normalizedLabel = TextSimilarityEngine.normalizeHomoglyphs(mainLabel);

        HashMap<String, BrandProfile> brands = BrandRepository.getBrandMap();
        for (BrandProfile brand : brands.values()) {
            // Check known typos or brand keywords appearing inside an unofficial domain
            ArrayList<String> typos = brand.getKnownTypos();
            for (int i = 0; i < typos.size(); i++) {
                String typo = typos.get(i);
                if (host.contains(typo) || normalizedHost.contains(typo)) {
                    int pos = lowerUrl.indexOf(typo);
                    String matched = (pos >= 0) ? typo : host;
                    result.addRedFlag(new RedFlag(
                            "URL_BRAND_TYPO",
                            "Brand Impersonation (" + brand.getDisplayName() + ")",
                            ScamCategory.PHISHING,
                            Severity.CRITICAL,
                            45,
                            matched,
                            pos,
                            pos >= 0 ? pos + matched.length() : -1,
                            "Unofficial domain imitates " + brand.getDisplayName() + " using lookalike/typo pattern '" + typo + "'."));
                    return;
                }
            }

            ArrayList<String> keywords = brand.getKeywords();
            for (int i = 0; i < keywords.size(); i++) {
                String kw = keywords.get(i);
                if (host.contains(kw) || normalizedHost.contains(kw)) {
                    int pos = lowerUrl.indexOf(kw);
                    result.addRedFlag(new RedFlag(
                            "URL_FAKE_BRAND",
                            "Unofficial Domain Using '" + brand.getDisplayName() + "' Name",
                            ScamCategory.PHISHING,
                            Severity.CRITICAL,
                            40,
                            kw,
                            pos,
                            pos >= 0 ? pos + kw.length() : -1,
                            "Host '" + host + "' contains '" + kw + "' but is NOT an official " + brand.getDisplayName() + " domain."));
                    return;
                }

                // 2D Edit Distance check for subtle 1-2 character typosquatting (e.g., "paytm" vs "paytn")
                if (kw.length() >= 4 && normalizedLabel.length() >= 4) {
                    int dist = TextSimilarityEngine.computeEditDistance(normalizedLabel, kw);
                    if (dist > 0 && dist <= 2) {
                        int pos = lowerUrl.indexOf(mainLabel);
                        result.addRedFlag(new RedFlag(
                                "URL_TYPOSQUAT_DIST",
                                "Typosquatting Near " + brand.getDisplayName(),
                                ScamCategory.PHISHING,
                                Severity.HIGH,
                                35,
                                mainLabel,
                                pos,
                                pos >= 0 ? pos + mainLabel.length() : -1,
                                "Domain label '" + mainLabel + "' is only " + dist + " character edit(s) away from '" + kw + "'."));
                        return;
                    }
                }
            }
        }
    }

    private void checkPhishingKeywords(String lowerUrl, ScanResult result) {
        for (int i = 0; i < PHISHING_PATH_KEYWORDS.length; i++) {
            String kw = PHISHING_PATH_KEYWORDS[i];
            int idx = lowerUrl.indexOf(kw);
            if (idx >= 0) {
                result.addRedFlag(new RedFlag(
                        "URL_PHISH_KEYWORD",
                        "Sensitive Action Keyword in URL ('" + kw + "')",
                        ScamCategory.PHISHING,
                        Severity.MEDIUM,
                        20,
                        kw,
                        idx,
                        idx + kw.length(),
                        "URL contains sensitive action term '" + kw + "', common in credential-harvesting links."));
                return;
            }
        }
    }

    private String extractHost(String lowerUrl) {
        String work = lowerUrl;
        int schemeEnd = work.indexOf("://");
        if (schemeEnd >= 0) {
            work = work.substring(schemeEnd + 3);
        }
        int atIdx = work.indexOf('@');
        if (atIdx >= 0) {
            work = work.substring(atIdx + 1);
        }
        int slashIdx = work.indexOf('/');
        if (slashIdx >= 0) {
            work = work.substring(0, slashIdx);
        }
        int queryIdx = work.indexOf('?');
        if (queryIdx >= 0) {
            work = work.substring(0, queryIdx);
        }
        int colonIdx = work.indexOf(':');
        if (colonIdx >= 0) {
            work = work.substring(0, colonIdx);
        }
        return work.trim();
    }

    private String extractPathAndQuery(String lowerUrl) {
        int schemeEnd = lowerUrl.indexOf("://");
        int start = (schemeEnd >= 0) ? schemeEnd + 3 : 0;
        int slashIdx = lowerUrl.indexOf('/', start);
        if (slashIdx >= 0) {
            return lowerUrl.substring(slashIdx);
        }
        return "";
    }

    private String extractMainDomainLabel(String host) {
        String clean = host.startsWith("www.") ? host.substring(4) : host;
        String[] parts = clean.split("\\.");
        if (parts.length >= 2) {
            return parts[0];
        }
        return clean;
    }

    private boolean isIpAddress(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String[] octets = host.split("\\.");
        if (octets.length != 4) {
            return false;
        }
        for (int i = 0; i < octets.length; i++) {
            String part = octets[i];
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            for (int j = 0; j < part.length(); j++) {
                if (!Character.isDigit(part.charAt(j))) {
                    return false;
                }
            }
            int val = Integer.parseInt(part);
            if (val < 0 || val > 255) {
                return false;
            }
        }
        return true;
    }
}
