package com.example.jwt_demo.dto;

import com.example.jwt_demo.model.Landmark;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class LandmarkDetail {
    private String id;
    private String name;
    private String location;
    private String imageUrl;
    private Double rating;
    private Integer reviewCount;
    private boolean isFavorite;
    private String category;
    private String bestTimeToVisit;
    private String entryFee;
    private String durationHours;
    private String description;
    private List<String> gallery;

    public static LandmarkDetail from(Landmark l, boolean isFavorite) {
        return new LandmarkDetail(
                l.getId(),
                l.getName(),
                l.getLocation(),
                l.getImageUrl(),
                l.getRating(),
                l.getReviewCount(),
                isFavorite,
                l.getCategory(),
                l.getBestTimeToVisit(),
                l.getEntryFee(),
                l.getDurationHours(),
                l.getDescription(),
                l.getGallery()
        );
    }
}
