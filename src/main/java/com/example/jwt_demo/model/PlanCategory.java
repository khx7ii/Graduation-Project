package com.example.jwt_demo.model;

public enum PlanCategory {
    HISTORICAL("Historical & Ancient"),
    BEACH("Beach & Diving"),
    DESERT("Desert & Adventure"),
    CITY("City & Shopping"),
    NILE_CRUISE("Nile Cruise"),
    CULTURAL("Cultural & Culinary");

    public static final PlanCategory DEFAULT = CULTURAL;

    private final String label;

    PlanCategory(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    /** Parse a known enum id (e.g. "HISTORICAL" / "nile_cruise"); null if not a valid value. */
    public static PlanCategory fromId(String id) {
        if (id == null) {
            return null;
        }
        String trimmed = id.trim();
        for (PlanCategory c : values()) {
            if (c.name().equalsIgnoreCase(trimmed)) {
                return c;
            }
        }
        return null;
    }

    /**
     * Fuzzy-match free-text (e.g. a chatty AI answer) to a category.
     * Falls back to {@link #DEFAULT} when nothing matches.
     */
    public static PlanCategory fromText(String text) {
        if (text == null || text.isBlank()) {
            return DEFAULT;
        }
        String upper = text.toUpperCase();
        for (PlanCategory c : values()) {
            if (upper.contains(c.name()) || upper.contains(c.name().replace('_', ' '))) {
                return c;
            }
        }
        for (PlanCategory c : values()) {
            if (upper.contains(c.label.toUpperCase())) {
                return c;
            }
        }
        return DEFAULT;
    }
}
