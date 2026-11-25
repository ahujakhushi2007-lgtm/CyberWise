package com.cyberwise.analyzer;

import com.cyberwise.model.RedFlag;
import com.cyberwise.model.Severity;

import java.util.Comparator;

/**
 * Custom Comparator sorting {@code RedFlag} items by weight descending, then severity rank descending.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * Interface implementation ({@code Comparator}), Polymorphism, {@code Collections.sort}.</p>
 */
public class RedFlagWeightComparator implements Comparator<RedFlag> {

    @Override
    public int compare(RedFlag first, RedFlag second) {
        int weightCmp = Integer.compare(second.getWeight(), first.getWeight());
        if (weightCmp != 0) {
            return weightCmp;
        }
        int sevCmp = Integer.compare(Severity.rank(second.getSeverity()), Severity.rank(first.getSeverity()));
        if (sevCmp != 0) {
            return sevCmp;
        }
        return first.getRuleName().compareTo(second.getRuleName());
    }
}
