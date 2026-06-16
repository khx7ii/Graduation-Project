package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.SuggestedPlanCard;
import com.example.jwt_demo.model.Landmark;
import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.LandmarkRepository;
import com.example.jwt_demo.repository.SuggestedPlanRepository;
import com.example.jwt_demo.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/favorites")
public class FavoriteController {

    private final UserService userService;
    private final SuggestedPlanRepository suggestedPlanRepository;
    private final LandmarkRepository landmarkRepository;

    public FavoriteController(UserService userService,
                              SuggestedPlanRepository suggestedPlanRepository,
                              LandmarkRepository landmarkRepository) {
        this.userService = userService;
        this.suggestedPlanRepository = suggestedPlanRepository;
        this.landmarkRepository = landmarkRepository;
    }

    @PostMapping("/{planId}")
    public ResponseEntity<Void> addFavorite(@AuthenticationPrincipal String email,
                                            @PathVariable String planId) {
        if (!suggestedPlanRepository.existsById(planId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found");
        }
        User user = requireUser(email);
        Set<String> favorites = planFavorites(user);
        favorites.add(planId);
        user.setFavoritePlanIds(favorites);
        userService.save(user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{planId}")
    public ResponseEntity<Void> removeFavorite(@AuthenticationPrincipal String email,
                                               @PathVariable String planId) {
        User user = requireUser(email);
        Set<String> favorites = planFavorites(user);
        favorites.remove(planId);
        user.setFavoritePlanIds(favorites);
        userService.save(user);
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    public ResponseEntity<List<SuggestedPlanCard>> myFavorites(@AuthenticationPrincipal String email) {
        User user = requireUser(email);
        List<SuggestedPlanCard> cards = new ArrayList<>();
        suggestedPlanRepository.findAllById(planFavorites(user))
                .forEach(p -> cards.add(SuggestedPlanCard.from(p)));
        return ResponseEntity.ok(cards);
    }

    @PostMapping("/landmarks/{landmarkId}")
    public ResponseEntity<Void> addLandmarkFavorite(@AuthenticationPrincipal String email,
                                                    @PathVariable String landmarkId) {
        if (!landmarkRepository.existsById(landmarkId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Landmark not found");
        }
        User user = requireUser(email);
        Set<String> favorites = landmarkFavorites(user);
        favorites.add(landmarkId);
        user.setFavoriteLandmarkIds(favorites);
        userService.save(user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/landmarks/{landmarkId}")
    public ResponseEntity<Void> removeLandmarkFavorite(@AuthenticationPrincipal String email,
                                                       @PathVariable String landmarkId) {
        User user = requireUser(email);
        Set<String> favorites = landmarkFavorites(user);
        favorites.remove(landmarkId);
        user.setFavoriteLandmarkIds(favorites);
        userService.save(user);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/landmarks")
    public ResponseEntity<List<Landmark>> myLandmarkFavorites(@AuthenticationPrincipal String email) {
        User user = requireUser(email);
        List<Landmark> result = new ArrayList<>();
        landmarkRepository.findAllById(landmarkFavorites(user)).forEach(result::add);
        return ResponseEntity.ok(result);
    }

    private User requireUser(String email) {
        return userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private Set<String> planFavorites(User user) {
        Set<String> favorites = user.getFavoritePlanIds();
        return favorites != null ? favorites : new HashSet<>();
    }

    private Set<String> landmarkFavorites(User user) {
        Set<String> favorites = user.getFavoriteLandmarkIds();
        return favorites != null ? favorites : new HashSet<>();
    }
}
