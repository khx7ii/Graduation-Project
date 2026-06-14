package com.example.jwt_demo.dto;

import com.example.jwt_demo.model.SavedPlan;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class PlanSummary {
    private String id;
    private String userId;
    private String title;
    private String category;
    private Object data;
    private LocalDateTime savedAt;
    private LocalDate startDate;
    private LocalDate endDate;
    private boolean active;

    public static PlanSummary from(SavedPlan p) {
        return new PlanSummary(
                p.getId(),
                p.getUserId(),
                p.getTitle(),
                p.getCategory(),
                p.getData(),
                p.getSavedAt(),
                p.getStartDate(),
                p.getEndDate(),
                p.getStartDate() != null
        );
    }
}
