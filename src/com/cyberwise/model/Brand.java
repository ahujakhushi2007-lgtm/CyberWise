package com.cyberwise.model;

import java.util.List;

public class Brand {
    private final String id;
    private final String name;
    private final List<String> domains;
    private final List<String> keywords;
    private final List<String> typos;

    public Brand(String id, String name, List<String> domains, List<String> keywords, List<String> typos) {
        this.id = id;
        this.name = name;
        this.domains = domains;
        this.keywords = keywords;
        this.typos = typos;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public List<String> getDomains() { return domains; }
    public List<String> getKeywords() { return keywords; }
    public List<String> getTypos() { return typos; }
}

