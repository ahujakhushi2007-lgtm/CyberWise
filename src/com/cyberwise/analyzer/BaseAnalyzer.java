package com.cyberwise.analyzer;

import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.AnalysisResult;

/**
 * Abstract Base Analyzer implementing common validation and logging logic (Lectures 1-5).
 */
public abstract class BaseAnalyzer<T> implements ThreatAnalyzer<T> {

    protected final String analyzerName;

    public BaseAnalyzer(String analyzerName) {
        this.analyzerName = analyzerName;
    }

    @Override
    public String getAnalyzerName() {
        return analyzerName;
    }

    /**
     * Template method with input validation before execution
     */
    @Override
    public AnalysisResult analyze(T input) throws InvalidInputException {
        validateInput(input);
        return doAnalyze(input);
    }

    protected abstract void validateInput(T input) throws InvalidInputException;

    protected abstract AnalysisResult doAnalyze(T input);
}

