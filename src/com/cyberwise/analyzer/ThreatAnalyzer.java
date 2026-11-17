package com.cyberwise.analyzer;

import com.cyberwise.exception.InvalidInputException;
import com.cyberwise.model.AnalysisResult;

/**
 * Generic Interface for all Threat Analyzers (Lectures 1-5 Abstraction, Lectures 47-48 Generics).
 * @param <T> Input artifact type (String, EmailInput, etc.)
 */
public interface ThreatAnalyzer<T> {
    AnalysisResult analyze(T input) throws InvalidInputException;
    String getAnalyzerName();
}

