package com.cyberwise.analyzer;

import com.cyberwise.data.RuleRepository;
import com.cyberwise.engine.RuleMatcher;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScamRule;
import com.cyberwise.model.ScanResult;
import com.cyberwise.service.DebugTracer;

import java.util.ArrayList;

/**
 * Analyzes SMS and WhatsApp messages using offline India-first scam rules and embedded URL inspection.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 2A, Unit 2B):</b>
 * Inheritance ({@code extends AbstractThreatAnalyzer}), Method Overriding ({@code performAnalysis}),
 * Composition (delegating embedded URLs to {@code LinkAnalyzer}), {@code ArrayList}.</p>
 */
public class SmsTextAnalyzer extends AbstractThreatAnalyzer {

    private final LinkAnalyzer embeddedLinkAnalyzer;

    public SmsTextAnalyzer() {
        super("SmsTextAnalyzer", "SMS");
        this.embeddedLinkAnalyzer = new LinkAnalyzer();
    }

    protected SmsTextAnalyzer(String analyzerName, String supportedType) {
        super(analyzerName, supportedType);
        this.embeddedLinkAnalyzer = new LinkAnalyzer();
    }

    @Override
    protected void performAnalysis(String input, ScanResult result) {
        ArrayList<ScamRule> rules = RuleRepository.getAllRules();
        ArrayList<RedFlag> matchedFlags = RuleMatcher.matchRules(input, rules);

        for (int i = 0; i < matchedFlags.size(); i++) {
            addDeduplicatedFlag(result, matchedFlags.get(i));
        }

        // Extract and scan any embedded URLs inside the SMS/message
        ArrayList<String> urls = RuleMatcher.extractUrls(input);
        DebugTracer.log(getAnalyzerName(), "Embedded URLs found: " + urls.size());

        for (int i = 0; i < urls.size(); i++) {
            String url = urls.get(i);
            try {
                ScanResult linkResult = this.embeddedLinkAnalyzer.analyze(url);
                ArrayList<RedFlag> linkFlags = linkResult.getRedFlags();
                int urlOffset = input.indexOf(url);

                for (int j = 0; j < linkFlags.size(); j++) {
                    RedFlag lf = linkFlags.get(j);
                    // Map embedded URL match span back onto the original SMS text for highlighting
                    int spanStart = (urlOffset >= 0) ? urlOffset : lf.getStartIndex();
                    int spanEnd = (urlOffset >= 0) ? urlOffset + url.length() : lf.getEndIndex();
                    String spanSlice = (urlOffset >= 0) ? url : lf.getMatchedText();

                    RedFlag remapped = new RedFlag(
                            "MSG_" + lf.getRuleId(),
                            "Embedded Link: " + lf.getRuleName(),
                            lf.getCategory(),
                            lf.getSeverity(),
                            lf.getWeight(),
                            spanSlice,
                            spanStart,
                            spanEnd,
                            lf.getExplanation());
                    addDeduplicatedFlag(result, remapped);
                }
            } catch (CyberWiseException e) {
                DebugTracer.log(getAnalyzerName(), "Skipped invalid embedded URL '" + url + "': " + e.getMessage());
            }
        }
    }
}
