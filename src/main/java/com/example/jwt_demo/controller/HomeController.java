package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.LandmarkDetail;
import com.example.jwt_demo.dto.SuggestedPlanCard;
import com.example.jwt_demo.model.Landmark;
import com.example.jwt_demo.model.PlanCategory;
import com.example.jwt_demo.model.SuggestedPlan;
import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.LandmarkRepository;
import com.example.jwt_demo.repository.SuggestedPlanRepository;
import com.example.jwt_demo.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/home")
public class HomeController {

    private final LandmarkRepository landmarkRepository;
    private final SuggestedPlanRepository suggestedPlanRepository;
    private final UserService userService;

    public HomeController(LandmarkRepository landmarkRepository,
                          SuggestedPlanRepository suggestedPlanRepository,
                          UserService userService) {
        this.landmarkRepository = landmarkRepository;
        this.suggestedPlanRepository = suggestedPlanRepository;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> home() {
        List<Landmark> trending = landmarkRepository.findAll();
        List<SuggestedPlanCard> suggested = suggestedPlanRepository.findAll().stream()
                .map(SuggestedPlanCard::from)
                .toList();
        return ResponseEntity.ok(Map.of(
                "trendingExpeditions", trending,
                "suggestedPlans", suggested
        ));
    }

    @GetMapping("/landmarks/{id}")
    public ResponseEntity<LandmarkDetail> getLandmark(@AuthenticationPrincipal String email,
                                                     @PathVariable String id) {
        Landmark landmark = landmarkRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Landmark not found"));

        boolean isFavorite = false;
        if (email != null) {
            User user = userService.findByEmail(email).orElse(null);
            if (user != null) {
                Set<String> favs = user.getFavoriteLandmarkIds();
                isFavorite = favs != null && favs.contains(id);
            }
        }
        return ResponseEntity.ok(LandmarkDetail.from(landmark, isFavorite));
    }

    @GetMapping("/suggested-plans/{id}")
    public ResponseEntity<SuggestedPlan> getSuggestedPlan(@PathVariable String id) {
        SuggestedPlan plan = suggestedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        return ResponseEntity.ok(plan);
    }

    @GetMapping("/categories")
    public ResponseEntity<List<Map<String, String>>> categories() {
        List<Map<String, String>> categories = Arrays.stream(PlanCategory.values())
                .map(c -> Map.of("id", c.name(), "label", c.getLabel()))
                .toList();
        return ResponseEntity.ok(categories);
    }

    @GetMapping("/plans/{category}")
    public ResponseEntity<List<SuggestedPlanCard>> plansByCategory(@PathVariable String category) {
        PlanCategory parsed = PlanCategory.fromId(category);
        if (parsed == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown category: " + category);
        }
        List<SuggestedPlanCard> cards = suggestedPlanRepository.findByCategory(parsed.name()).stream()
                .map(SuggestedPlanCard::from)
                .toList();
        return ResponseEntity.ok(cards);
    }
}
