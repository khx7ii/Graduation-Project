package com.example.jwt_demo.dto;

import lombok.Data;

@Data
public class AddPlaceRequest {
    private Integer dayIndex;
    private String placeId;
    private String time;
}
