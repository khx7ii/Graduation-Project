package com.example.jwt_demo.dto;

import lombok.Data;

@Data
public class DeletePlaceRequest {
    private Integer dayIndex;
    private Integer activityIndex;
}
