package com.cyberwise.analyzer;

import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Finding;
import com.cyberwise.model.Verdict;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Text / SMS / WhatsApp threat analyzer extending BaseAnalyzer (Lectures 1-5, 6-9, 10-12).
 */
public class TextAnalyzer extends BaseAnalyzer<String> {

    private static final Pattern DIGITAL_ARREST = Pattern.compile(
        "(\\b(digital\\s*arrest|arrest\\s*warrant|cbi(\\s*crime\\s*branch|\\s*officer|\\s*notice)?|narcotics\\s*control\\s*bureau|ncb|customs\\s*department|supreme\\s*court\\s*notice|non-bailable\\s*warrant|money\\s*laundering\\s*case|police\\s*interrogation|skype\\s*(interrogation|call|investigation)|digital\\s*custody|swat\\s*(team|police\\s*raid))\\b|(गिरफ्तारी\\s*वारंट|सीबीआई|नारकोटिक्स|कस्टम्स|मनी\\s*लॉन्ड्रिंग|डिजिटल\\s*अरेस्ट))",
        Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    private static final Pattern ELECTRICITY_CUT = Pattern.compile(
        "(\\b(electricity\\s*(power|bill|connection)\\s*(will\\s*be\\s*disconnected|cut|suspended)|disconnection\\s*at\\s*9[:.]30\\s*pm|power\\s*will\\s*be\\s*cut\\s*tonight|call\\s*electricity\\s*officer|discom\\s*officer)\\b|(बिजली\\s*(काट\\s*दी\\s*जाएगी|बिल|कनेक्शन\\s*काट)|आज\\s*रात\\s*(9|नौ)[:.]30|बिजली\\s*(अधिकारी|ऑफिसर)\\s*से\\s*संपर्क|पिछले\\s*माह\\s*का\\s*बिल))",
        Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    private static final Pattern FAKE_KYC = Pattern.compile(
        "(\\b(account\\s*(has\\s*been|will\\s*be|is)\\s*(blocked|suspended|deactivated|frozen)|yono\\s*(account|sbi|user)?|update\\s*(your\\s*)?(pan|aadhaar|kyc)\\s*(immediately|urgently|today)?|submit\\s*kyc\\s*documents|link\\s*pan\\s*with\\s*aadhaar|card\\s*has\\s*been\\s*deactivated)\\b|(खाता\\s*(बंद|ब्लॉक|सस्पेंड)|केवाईसी\\s*अपडेट\\s*करें|पैन\\s*कार्ड\\s*(लिंक|अपडेट)|pan\\s*card\\s*update\\s*karein|khata\\s*block\\s*hoga))",
        Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    private static final Pattern UPI_PIN_TRAP = Pattern.compile(
        "(\\b(enter\\s*(your\\s*)?(secret\\s*|4-digit\\s*|6-digit\\s*)?upi\\s*pin\\s*(to\\s*(receive|get|claim)|and|to\\s*get)|scan\\s*qr\\s*(code\\s*)?(and\\s*enter|to\\s*receive|to\\s*get)|cashback\\s*of\\s*(rs\\.?|inr|₹)\\s*[\\d,]+|(won|claim|received)\\s*(a\\s*)?(pending\\s*)?(cashback|refund)\\s*(of\\s*(rs\\.?|inr|₹))?\\s*[\\d,]*|phonepe\\s*reward|gpay\\s*cashback)\\b|(पैसे\\s*पाने\\s*के\\s*लिए\\s*पिन|रिफंड\\s*स्वीकार\\s*करें|upi\\s*pin\\s*dalein|paise\\s*receive\\s*karne\\s*ke\\s*liye\\s*pin))",
        Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    private static final Pattern REMOTE_ACCESS = Pattern.compile(
        "\\b(anydesk|teamviewer|rustdesk|quicksupport|air\\s*droid|screenshare\\s*app|install\\s*support\\s*app)\\b",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern COURIER_DRUGS = Pattern.compile(
        "\\b(parcel\\s*(contains|seized|intercepted)|drugs|narcotics\\s*found|illegal\\s*substance|customs\\s*clearance\\s*fine|package\\s*held\\s*at\\s*(mumbai|delhi)\\s*airport|taiwan\\s*consignment|fedex\\s*customs)\\b",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern TELEGRAM_JOB = Pattern.compile(
        "\\b(earn\\s*(rs\\.?|inr|₹)\\s*[\\d,]+\\s*daily|like\\s*youtube\\s*videos|rate\\s*google\\s*maps|part-time\\s*(job|work\\s*from\\s*home|freelancer)|contact\\s*hr\\s*manager\\s*on\\s*telegram|prepaid\\s*task|earn\\s*from\\s*home\\s*30\\s*mins|@earndaily|@priya_hr|freelancers\\s*for\\s*simple\\s*online\\s*tasks)\\b",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern KBC_LOTTERY = Pattern.compile(
        "\\b(kbc(\\s*[0-9]{4})?\\s*(lucky\\s*draw|winner|lottery)?|won\\s*(rs\\.?|inr|₹)?\\s*(25|50)\\s*(lakh|crore)|(25|50)\\s*(lakh|crore)\\s*(ki\\s*)?lottery|amitabh\\s*bachchan\\s*lottery|processing\\s*fee\\s*(rs\\.?|to\\s*claim)|lottery\\s*winner\\s*202[0-9]|prize\\s*money\\s*claim)\\b",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URGENCY = Pattern.compile(
        "\\b(act\\s*now|immediately|within\\s*(24|12|2|1)\\s*hours|urgent\\s*notice|last\\s*warning|final\\s*reminder|today\\s*itself|before\\s*it\\s*is\\s*too\\s*late|action\\s*required|आज\\s*ही|तुरंत|अंतिम\\s*चेतावनी)\\b",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
        "(https?://[^\\s]+|www\\.[^\\s]+|[a-zA-Z0-9-]+\\.(?:com|in|co\\.in|org|net|xyz|top|click|live|icu|site|club|app|biz|ru|cn|cc)[^\\s]*)",
        Pattern.CASE_INSENSITIVE
    );

    public TextAnalyzer() {
        super("TextAnalyzer Engine");
    }

    @Override
    protected void validateInput(String input) throws InvalidInputException {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidInputException("Message text cannot be empty or null.", "TEXT");
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
    public static AnalysisResult scan(String rawText) {
        return analyzeStatic(rawText);
    }

    public static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null) return urls;
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String u = matcher.group().replaceAll("[.,;!?)]+$", "");
            if (!urls.contains(u)) urls.add(u);
        }
        return urls;
    }

    private static AnalysisResult analyzeStatic(String rawText) {
        String text = (rawText == null) ? "" : rawText.trim();
        AnalysisResult result = new AnalysisResult(text, "TEXT");

        if (text.isEmpty()) {
            result.addFinding(new Finding("empty_text", "Empty Message Content", "LOW", 0, "No text content provided for analysis."));
            result.setExplanation("Empty text provided.");
            return result;
        }

        int score = 0;

        // 1. Digital Arrest
        if (DIGITAL_ARREST.matcher(text).find()) {
            score += 55;
            result.setScamType("digital_arrest");
            result.setImpersonatedBrand("Law Enforcement (CBI/Police)");
            result.addFinding(new Finding("digital_arrest_pattern", "Digital Arrest & Police Extortion Threat", "CRITICAL", 55,
                "Extortion tactic impersonating CBI/Courts. Indian law enforcement and courts NEVER conduct online video arrests or demand verification deposits."));
            result.addTactic("Legal & Coercion Threat");
            result.addTactic("Fear Induction");
        }

        // 2. Electricity Disconnection
        if (ELECTRICITY_CUT.matcher(text).find()) {
            score += 65;
            result.setScamType("electricity_cut");
            result.setImpersonatedBrand("State Electricity Board (Discom)");
            result.addFinding(new Finding("electricity_cut_threat", "Fake Electricity Disconnection Warning", "CRITICAL", 65,
                "False power disconnection ultimatum (e.g. 9:30 PM). State electricity discoms never issue 2-hour disconnection threats via personal mobile numbers."));
            result.addTactic("Artificial Panic Induction");
            result.addTactic("Discom Impersonation");
        }

        // 3. Fake Bank KYC
        if (FAKE_KYC.matcher(text).find()) {
            score += 40;
            result.setScamType("fake_kyc");
            result.addFinding(new Finding("fake_kyc_suspension", "Fake Bank Account / KYC Suspension Notice", "CRITICAL", 40,
                "Deceptive notice claiming account will be deactivated unless PAN/Aadhaar is submitted on an external unverified form."));
            result.addTactic("Account Deactivation Threat");
            result.addTactic("Credential Harvesting");
        }

        // 4. UPI PIN Trap
        if (UPI_PIN_TRAP.matcher(text).find()) {
            score += 65;
            result.setScamType("upi_refund");
            result.setImpersonatedBrand("UPI / PhonePe / GPay");
            result.addFinding(new Finding("upi_pin_trap", "UPI PIN / Reverse QR Extortion Trap", "CRITICAL", 65,
                "Crucial UPI Golden Rule: UPI PIN is entered ONLY to SEND/DEBIT money, NEVER to receive funds or cashbacks!"));
            result.addTactic("Credential & PIN Extraction");
            result.addTactic("Greed Appeal");
        }

        // 5. Remote Access Software
        if (REMOTE_ACCESS.matcher(text).find()) {
            score += 60;
            result.setScamType("remote_access_takeover");
            result.addFinding(new Finding("remote_access_tool", "Remote Screen Sharing Tool Requested (AnyDesk/TeamViewer)", "CRITICAL", 60,
                "Demanding victims install AnyDesk or TeamViewer allows scammers to mirror smartphone screens and intercept banking OTPs in real-time."));
            result.addTactic("Device Takeover Attempt");
        }

        // 6. Courier Contraband
        if (COURIER_DRUGS.matcher(text).find()) {
            score += 65;
            result.setScamType("courier_customs");
            result.setImpersonatedBrand("FedEx / Customs");
            result.addFinding(new Finding("courier_contraband", "Courier Parcel Drug Contraband Extortion", "CRITICAL", 65,
                "Fabricated claim that international packages contained contraband narcotics. Legitimate couriers do not accuse recipients of drug smuggling over phone calls."));
            result.addTactic("Authority Coercion");
        }

        // 7. Telegram Job Fraud
        if (TELEGRAM_JOB.matcher(text).find()) {
            score += 45;
            result.setScamType("job_offer");
            result.addFinding(new Finding("telegram_job_scam", "Part-time YouTube Rating / Telegram Task Fraud", "HIGH", 45,
                "Promises unrealistic daily income (₹3000-₹8000) for rating Google Maps or liking YouTube videos, funnelling victims into advance prepaid deposit extortion."));
            result.addTactic("Unrealistic Financial Reward");
            result.addTactic("Prepaid Task Funnel");
        }

        // 8. KBC / Lottery
        if (KBC_LOTTERY.matcher(text).find()) {
            score += 55;
            result.setScamType("lottery_kbc");
            result.setImpersonatedBrand("KBC / Amitabh Bachchan");
            result.addFinding(new Finding("lottery_kbc_fraud", "KBC / WhatsApp Lottery Winner Scam", "HIGH", 55,
                "Advance-fee fraud claiming random mobile numbers won ₹25-50 Lakh in a lottery, demanding upfront 'processing/GST fees'."));
            result.addTactic("Advance-Fee Fraud");
        }

        // 9. Urgency
        if (URGENCY.matcher(text).find()) {
            score += 15;
            result.addFinding(new Finding("artificial_urgency", "Artificial Time-Pressure / Panic Inducer", "MEDIUM", 15,
                "Attackers use artificial urgency ('within 24 hours', 'act now') to bypass logical critical thinking."));
            result.addTactic("Artificial Urgency");
        }

        // 10. Embedded Links
        List<String> links = extractUrls(text);
        boolean hasSafeOfficialLinkOnly = false;
        if (!links.isEmpty()) {
            boolean allOfficial = true;
            for (String link : links) {
                AnalysisResult linkRes = UrlAnalyzer.scan(link);
                if (linkRes.getVerdict() == Verdict.DANGEROUS || linkRes.getVerdict() == Verdict.SUSPICIOUS) {
                    allOfficial = false;
                    score += (int) Math.round(linkRes.getRiskScore() * 0.45);
                    result.addFinding(new Finding("embedded_malicious_link", "Malicious Link Embedded: " + linkRes.getTarget(), "CRITICAL",
                        (int) Math.round(linkRes.getRiskScore() * 0.45),
                        "Embedded URL flagged as " + linkRes.getVerdict() + " with risk score " + linkRes.getRiskScore() + "/100."));
                    result.addTactic("Phishing Link Redirection");
                }
            }
            if (allOfficial) {
                hasSafeOfficialLinkOnly = true;
            }
        }

        // 11. Real Bank Transaction Discount
        boolean isRealBankDebit = Pattern.compile("\\b(debited\\s*from|credited\\s*to)\\b", Pattern.CASE_INSENSITIVE).matcher(text).find()
            && Pattern.compile("\\b(a/c|account)\\s*(ending\\s*with|\\*\\*|\\bno\\b)", Pattern.CASE_INSENSITIVE).matcher(text).find()
            && Pattern.compile("\\b(available\\s*balance|balance:?)\\b", Pattern.CASE_INSENSITIVE).matcher(text).find();

        boolean isRealBillNotice = Pattern.compile("\\b(monthly|generated|due\\s*date|bill\\s*of)\\b", Pattern.CASE_INSENSITIVE).matcher(text).find()
            && hasSafeOfficialLinkOnly
            && !Pattern.compile("\\b(disconnect|cut|block|suspend)\\b", Pattern.CASE_INSENSITIVE).matcher(text).find();

        if ((isRealBankDebit || isRealBillNotice) && score <= 35) {
            score = 0;
            result.getFindings().clear();
            result.getTactics().clear();
            result.setScamType(null);
        }

        result.setRiskScore(score);

        if (result.getVerdict() == Verdict.DANGEROUS) {
            result.setExplanation("CRITICAL FRAUD ALERT: High-confidence scam detected. This message employs psychological coercion, unauthorized authority claims, or financial traps to compromise your bank account.");
            result.setExplanationHi("उच्च जोखिम वाला फ्रॉड संदेश पकड़ा गया! यह संदेश आपको डराकर या लालच देकर बैंक विवरण या ओटीपी चुराने के लिए बनाया गया है।");
            result.addRecommendedAction("Do NOT click any links, call provided numbers, or transfer funds.");
            result.addRecommendedAction("NEVER share OTP, UPI PIN, or passwords with anyone.");
            result.addRecommendedAction("Report incident immediately to National Cybercrime Helpline 1930 and file complaint at https://cybercrime.gov.in.");
            result.addRecommendedAction("Report suspect numbers/SMS on Sanchar Saathi Chakshu portal (https://sancharsaathi.gov.in).");
        } else if (result.getVerdict() == Verdict.SUSPICIOUS) {
            result.setExplanation("SUSPICIOUS MESSAGE: Contains urgency cues or unverified financial solicitations that warrant verification.");
            result.setExplanationHi("संदिग्ध संदेश: इसमें जल्दबाजी में निर्णय लेने का दबाव है। कोई भी विवरण साझा न करें।");
            result.addRecommendedAction("Verify sender through official institutional customer service before responding.");
        } else {
            result.setExplanation("SAFE COMMUNICATION: No phishing or coercive psychological manipulation patterns detected.");
            result.setExplanationHi("विश्लेषण में कोई भी ठगी या संदिग्ध दबाव के लक्षण नहीं मिले। यह सुरक्षित प्रतीत होता है।");
            result.addRecommendedAction("Conforms to normal communication standards. Maintain standard digital hygiene.");
        }

        result.sortFindingsBySeverity();
        return result;
    }
}
