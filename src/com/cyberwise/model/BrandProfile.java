package com.cyberwise.model;

import java.util.ArrayList;
import java.util.HashSet;

/**
 * Domain model representing a trusted Indian bank, payment app, government portal, or brand.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2B):</b>
 * Classes and Objects, Encapsulation, Constructors with {@code this},
 * {@code HashSet} for fast domain lookup, {@code ArrayList} for keywords and typos.</p>
 */
public class BrandProfile {

    private final String id;
    private final String displayName;
    private final HashSet<String> officialDomains;
    private final ArrayList<String> keywords;
    private final ArrayList<String> knownTypos;

    public BrandProfile(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
        this.officialDomains = new HashSet<String>();
        this.keywords = new ArrayList<String>();
        this.knownTypos = new ArrayList<String>();
    }

    /**
     * Overloaded constructor initializing all collections directly.
     */
    public BrandProfile(String id, String displayName,
                        HashSet<String> officialDomains,
                        ArrayList<String> keywords,
                        ArrayList<String> knownTypos) {
        this.id = id;
        this.displayName = displayName;
        this.officialDomains = officialDomains;
        this.keywords = keywords;
        this.knownTypos = knownTypos;
    }

    public void addOfficialDomain(String domain) {
        this.officialDomains.add(domain.toLowerCase());
    }

    public void addKeyword(String keyword) {
        this.keywords.add(keyword.toLowerCase());
    }

    public void addKnownTypo(String typo) {
        this.knownTypos.add(typo.toLowerCase());
    }

    public String getId() {
        return this.id;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public HashSet<String> getOfficialDomains() {
        return this.officialDomains;
    }

    public ArrayList<String> getKeywords() {
        return this.keywords;
    }

    public ArrayList<String> getKnownTypos() {
        return this.knownTypos;
    }

    @Override
    public String toString() {
        return String.format("BrandProfile[id=%s, name=%s, domains=%d]",
                this.id, this.displayName, this.officialDomains.size());
    }
}
