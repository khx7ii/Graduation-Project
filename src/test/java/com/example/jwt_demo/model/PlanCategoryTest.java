package com.example.jwt_demo.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PlanCategoryTest {

    @Test
    void fromId_validValue_caseInsensitive() {
        assertThat(PlanCategory.fromId("HISTORICAL")).isEqualTo(PlanCategory.HISTORICAL);
        assertThat(PlanCategory.fromId("nile_cruise")).isEqualTo(PlanCategory.NILE_CRUISE);
        assertThat(PlanCategory.fromId("  beach  ")).isEqualTo(PlanCategory.BEACH);
    }

    @Test
    void fromId_unknownOrNull_returnsNull() {
        assertThat(PlanCategory.fromId("space")).isNull();
        assertThat(PlanCategory.fromId(null)).isNull();
    }

    @Test
    void fromText_exactEnumName() {
        assertThat(PlanCategory.fromText("HISTORICAL")).isEqualTo(PlanCategory.HISTORICAL);
    }

    @Test
    void fromText_chattyAnswer_extractsCategory() {
        assertThat(PlanCategory.fromText("This plan is mostly about the CITY and shopping."))
                .isEqualTo(PlanCategory.CITY);
    }

    @Test
    void fromText_spacedNileCruise_matches() {
        assertThat(PlanCategory.fromText("I would say Nile Cruise"))
                .isEqualTo(PlanCategory.NILE_CRUISE);
    }

    @Test
    void fromText_matchesByLabel() {
        assertThat(PlanCategory.fromText("Beach & Diving")).isEqualTo(PlanCategory.BEACH);
    }

    @Test
    void fromText_noMatchOrBlank_returnsDefault() {
        assertThat(PlanCategory.fromText("completely unrelated text")).isEqualTo(PlanCategory.DEFAULT);
        assertThat(PlanCategory.fromText("")).isEqualTo(PlanCategory.DEFAULT);
        assertThat(PlanCategory.fromText(null)).isEqualTo(PlanCategory.DEFAULT);
    }
}
