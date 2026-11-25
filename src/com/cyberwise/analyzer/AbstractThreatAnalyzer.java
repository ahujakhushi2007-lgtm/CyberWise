package com.cyberwise.analyzer;

import com.cyberwise.engine.NextStepsAdvisor;
import com.cyberwise.engine.RiskScoringMatrix;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.RedFlag;
import com.cyberwise.model.ScanResult;
import com.cyberwise.service.DebugTracer;
import com.cyberwise.service.InputValidator;

import java.util.ArrayList;
import java.util.Collections;

/**
 * Abstract base class providing common validation, sorting, scoring, and next-step generation
 * for all concrete threat analyzers.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 2A, Unit 2B):</b>
 * Abstract Classes and Concrete/Abstract Methods, {@code this} keyword,
 * Exception Propagation ({@code throws}), {@code Collections.sort} with {@code Comparator}.</p>
 */
public abstract class AbstractThreatAnalyzer implements ThreatAnalyzer {

    private final String analyzerName;
    private final String supportedType;

    protected AbstractThreatAnalyzer(String analyzerName, String supportedType) {
        this.analyzerName = analyzerName;
        this.supportedType = supportedType;
    }

    @Override
    public final ScanResult analyze(String input) throws CyberWiseException {
        DebugTracer.log(this.analyzerName, "Validating input...");
        String validatedInput = validateInput(input);

        ScanResult result = new ScanResult(this.supportedType, validatedInput);
        DebugTracer.log(this.analyzerName, "Running performAnalysis on Scan #" + result.getScanId());

        performAnalysis(validatedInput, result);

        // Sort red flags by weight descending using explicit Comparator (Unit 2B)
        Collections.sort(result.getRedFlags(), new RedFlagWeightComparator());

        // Finalize score & primary category via 2D RiskScoringMatrix
        RiskScoringMatrix.finalizeScore(result);

        // Attach customized India-first next steps
        ArrayList<String> advice = NextStepsAdvisor.getAdvice(
                result.getPrimaryCategory(), result.getVerdict());
        result.setNextSteps(advice);

        DebugTracer.log(this.analyzerName,
                "Finished Scan #" + result.getScanId() + " -> Score=" + result.getRiskScore());
        return result;
    }

    /**
     * Subclasses may override to enforce specialized input rules (e.g., URL validation).
     */
    protected String validateInput(String input) throws InvalidInputException {
        return InputValidator.validateNonEmpty(input, this.supportedType);
    }

    /**
     * Abstract hook implemented by each concrete analyzer subclass.
     */
    protected abstract void performAnalysis(String input, ScanResult result);

    @Override
    public String getAnalyzerName() {
        return this.analyzerName;
    }

    @Override
    public String getSupportedType() {
        return this.supportedType;
    }

    protected void addDeduplicatedFlag(ScanResult result, RedFlag candidate) {
        ArrayList<RedFlag> existing = result.getRedFlags();
        for (int i = 0; i < existing.size(); i++) {
            if (existing.get(i).getRuleId().equals(candidate.getRuleId())) {
                return;
            }
        }
        result.addRedFlag(candidate);
    }
}
