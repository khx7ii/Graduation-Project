package com.example.jwt_demo.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.List;

@Data
@Document(collection = "landmarks")
public class Landmark {

    @Id
    private String id;

    private String name;
    private String subtitle;
    private String imageUrl;
    private Double lat;
    private Double lng;

    private String location;
    private Double rating;
    private Integer reviewCount;
    private String category;
    private String bestTimeToVisit;
    private String entryFee;
    private String durationHours;
    private String description;
    private List<String> gallery = new ArrayList<>();
}
