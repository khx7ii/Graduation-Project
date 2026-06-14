package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.AIReply;
import com.example.jwt_demo.dto.ActivatePlanRequest;
import com.example.jwt_demo.dto.AddPlaceRequest;
import com.example.jwt_demo.dto.DeletePlaceRequest;
import com.example.jwt_demo.dto.EditPlanRequest;
import com.example.jwt_demo.dto.PlanSummary;
import com.example.jwt_demo.dto.SavePlanRequest;
import com.example.jwt_demo.exception.AIServiceException;
import com.example.jwt_demo.model.Landmark;
import com.example.jwt_demo.model.SavedPlan;
import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.LandmarkRepository;
import com.example.jwt_demo.repository.SavedPlanRepository;
import com.example.jwt_demo.service.AIService;
import com.example.jwt_demo.service.PlanCategoryClassifier;
import com.example.jwt_demo.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/plans")
public class SavedPlanController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SavedPlanRepository savedPlanRepository;
    private final UserService userService;
    private final AIService aiService;
    private final LandmarkRepository landmarkRepository;
    private final PlanCategoryClassifier categoryClassifier;

    public SavedPlanController(SavedPlanRepository savedPlanRepository,
                               UserService userService,
                               AIService aiService,
                               LandmarkRepository landmarkRepository,
                               PlanCategoryClassifier categoryClassifier) {
        this.savedPlanRepository = savedPlanRepository;
        this.userService = userService;
        this.aiService = aiService;
        this.landmarkRepository = landmarkRepository;
        this.categoryClassifier = categoryClassifier;
    }

    @PostMapping("/save")
    public ResponseEntity<SavedPlan> save(
            @AuthenticationPrincipal String email,
            @RequestBody SavePlanRequest request) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        SavedPlan plan = new SavedPlan();
        plan.setUserId(user.getId());
        plan.setTitle(request.getTitle());
        plan.setData(request.getData());
        plan.setCategory(categoryClassifier.classify(request.getData()).name());
        plan.setSavedAt(LocalDateTime.now());
        return ResponseEntity.ok(savedPlanRepository.save(plan));
    }

    @GetMapping
    public ResponseEntity<List<PlanSummary>> myPlans(@AuthenticationPrincipal String email) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        List<PlanSummary> plans = savedPlanRepository.findByUserId(user.getId()).stream()
                .map(PlanSummary::from)
                .toList();
        return ResponseEntity.ok(plans);
    }

    @PostMapping("/{id}/edit")
    public ResponseEntity<SavedPlan> edit(
            @AuthenticationPrincipal String email,
            @PathVariable String id,
            @RequestBody EditPlanRequest request) {

        if (request.getInstruction() == null || request.getInstruction().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Instruction is required");
        }

        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        SavedPlan plan = savedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        if (!user.getId().equals(plan.getUserId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your plan");
        }

        String currentPlanJson;
        try {
            currentPlanJson = MAPPER.writeValueAsString(plan.getData());
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to serialize plan");
        }

        List<Map<String, String>> history = List.of(Map.of(
                "role", "Soli",
                "content", currentPlanJson
        ));

        AIReply reply = aiService.getReply(request.getInstruction(), null, "plan", history);

        if (!"plan".equals(reply.getType()) || reply.getData() == null) {
            throw new AIServiceException("AI did not return an updated plan");
        }

        plan.setData(reply.getData());
        plan.setCategory(categoryClassifier.classify(reply.getData()).name());
        plan.setSavedAt(LocalDateTime.now());
        return ResponseEntity.ok(savedPlanRepository.save(plan));
    }

    @PostMapping("/{id}/activate")
    public ResponseEntity<?> activate(
            @AuthenticationPrincipal String email,
            @PathVariable String id,
            @RequestBody ActivatePlanRequest request) {

        if (request.getStartDate() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "startDate is required");
        }
        if (request.getStartDate().isBefore(LocalDate.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "startDate cannot be in the past");
        }

        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        SavedPlan plan = savedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        if (!user.getId().equals(plan.getUserId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your plan");
        }

        int dayCount = countDays(plan.getData());
        if (dayCount <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Plan has no days");
        }

        LocalDate start = request.getStartDate();
        LocalDate end = start.plusDays(dayCount - 1);

        for (SavedPlan other : savedPlanRepository.findByUserIdAndStartDateNotNull(user.getId())) {
            if (other.getId().equals(plan.getId())) continue;
            if (other.getStartDate() == null || other.getEndDate() == null) continue;
            boolean overlap = !start.isAfter(other.getEndDate()) && !end.isBefore(other.getStartDate());
            if (overlap) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                        "error", "OVERLAP",
                        "message", "This plan overlaps with another active plan",
                        "conflictsWith", Map.of(
                                "id", other.getId(),
                                "title", other.getTitle(),
                                "startDate", other.getStartDate().toString(),
                                "endDate", other.getEndDate().toString()
                        )
                ));
            }
        }

        plan.setStartDate(start);
        plan.setEndDate(end);
        savedPlanRepository.save(plan);

        return ResponseEntity.ok(Map.of(
                "status", "OK",
                "startDate", start.toString(),
                "endDate", end.toString()
        ));
    }

    @PostMapping("/{id}/deactivate")
    public ResponseEntity<SavedPlan> deactivate(
            @AuthenticationPrincipal String email,
            @PathVariable String id) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        SavedPlan plan = savedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        if (!user.getId().equals(plan.getUserId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your plan");
        }
        plan.setStartDate(null);
        plan.setEndDate(null);
        return ResponseEntity.ok(savedPlanRepository.save(plan));
    }

    @PostMapping("/{id}/places")
    public ResponseEntity<SavedPlan> addPlace(
            @AuthenticationPrincipal String email,
            @PathVariable String id,
            @RequestBody AddPlaceRequest request) {

        if (request.getPlaceId() == null || request.getPlaceId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "placeId is required");
        }
        if (request.getDayIndex() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "dayIndex is required");
        }

        SavedPlan plan = requireOwnedPlan(email, id);
        Landmark place = landmarkRepository.findById(request.getPlaceId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Place not found"));

        List<Map<String, Object>> days = getDays(plan.getData());
        int dayIndex = request.getDayIndex();
        if (dayIndex < 0 || dayIndex >= days.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "dayIndex out of range");
        }

        Map<String, Object> activity = new HashMap<>();
        activity.put("time", request.getTime() != null ? request.getTime() : "");
        activity.put("title", place.getName());
        activity.put("description", place.getSubtitle());
        activity.put("cost_usd", 0);
        activity.put("cost_egp", 0);
        activity.put("lat", place.getLat());
        activity.put("lng", place.getLng());
        activity.put("category", "attraction");

        getActivities(days.get(dayIndex)).add(activity);
        return ResponseEntity.ok(savedPlanRepository.save(plan));
    }

    @DeleteMapping("/{id}/places")
    public ResponseEntity<SavedPlan> deletePlace(
            @AuthenticationPrincipal String email,
            @PathVariable String id,
            @RequestBody DeletePlaceRequest request) {

        if (request.getDayIndex() == null || request.getActivityIndex() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "dayIndex and activityIndex are required");
        }

        SavedPlan plan = requireOwnedPlan(email, id);
        List<Map<String, Object>> days = getDays(plan.getData());
        int dayIndex = request.getDayIndex();
        if (dayIndex < 0 || dayIndex >= days.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "dayIndex out of range");
        }

        Map<String, Object> day = days.get(dayIndex);
        List<Map<String, Object>> activities = getActivities(day);
        int activityIndex = request.getActivityIndex();
        if (activityIndex < 0 || activityIndex >= activities.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "activityIndex out of range");
        }

        Map<String, Object> removed = activities.remove(activityIndex);
        day.put("total_cost_usd", asDouble(day.get("total_cost_usd")) - asDouble(removed.get("cost_usd")));
        day.put("total_cost_egp", asDouble(day.get("total_cost_egp")) - asDouble(removed.get("cost_egp")));

        return ResponseEntity.ok(savedPlanRepository.save(plan));
    }

    private SavedPlan requireOwnedPlan(String email, String id) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        SavedPlan plan = savedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        if (!user.getId().equals(plan.getUserId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your plan");
        }
        return plan;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getDays(Object data) {
        if (!(data instanceof Map<?, ?> map)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Plan has no data");
        }
        Object days = ((Map<String, Object>) map).get("days");
        if (!(days instanceof List<?>)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Plan has no days");
        }
        return (List<Map<String, Object>>) days;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getActivities(Map<String, Object> day) {
        Object activities = day.get("activities");
        if (activities instanceof List<?>) {
            return (List<Map<String, Object>>) activities;
        }
        List<Map<String, Object>> created = new ArrayList<>();
        day.put("activities", created);
        return created;
    }

    private double asDouble(Object value) {
        return value instanceof Number n ? n.doubleValue() : 0.0;
    }

    @SuppressWarnings("unchecked")
    private int countDays(Object data) {
        if (!(data instanceof Map<?, ?> map)) return 0;
        Object days = ((Map<String, Object>) map).get("days");
        if (!(days instanceof List<?> list)) return 0;
        return list.size();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(
            @AuthenticationPrincipal String email,
            @PathVariable String id) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        SavedPlan plan = savedPlanRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Plan not found"));
        if (!user.getId().equals(plan.getUserId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not your plan");
        }
        savedPlanRepository.delete(plan);
        return ResponseEntity.noContent().build();
    }
}
