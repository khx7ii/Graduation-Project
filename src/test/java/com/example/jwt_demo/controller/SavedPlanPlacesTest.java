package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.AddPlaceRequest;
import com.example.jwt_demo.dto.DeletePlaceRequest;
import com.example.jwt_demo.model.Landmark;
import com.example.jwt_demo.model.SavedPlan;
import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.LandmarkRepository;
import com.example.jwt_demo.repository.SavedPlanRepository;
import com.example.jwt_demo.service.AIService;
import com.example.jwt_demo.service.PlanCategoryClassifier;
import com.example.jwt_demo.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SavedPlanPlacesTest {

    @Mock private SavedPlanRepository savedPlanRepository;
    @Mock private UserService userService;
    @Mock private AIService aiService;
    @Mock private LandmarkRepository landmarkRepository;
    @Mock private PlanCategoryClassifier categoryClassifier;

    @InjectMocks private SavedPlanController controller;

    private User user(String id) {
        User u = new User();
        u.setId(id);
        return u;
    }

    private Landmark landmark(String id) {
        Landmark l = new Landmark();
        l.setId(id);
        l.setName("Pyramids of Giza");
        l.setSubtitle("Ancient wonder");
        l.setLat(29.9792);
        l.setLng(31.1342);
        return l;
    }

    /** One day with the given activities; costs are mutable HashMaps so the controller can edit them. */
    private SavedPlan planWithOneDay(String userId, List<Map<String, Object>> activities,
                                     double totalUsd, double totalEgp) {
        Map<String, Object> day = new HashMap<>();
        day.put("total_cost_usd", totalUsd);
        day.put("total_cost_egp", totalEgp);
        day.put("activities", new ArrayList<>(activities));

        Map<String, Object> data = new HashMap<>();
        data.put("title", "Trip");
        data.put("days", new ArrayList<>(List.of(day)));

        SavedPlan plan = new SavedPlan();
        plan.setId("plan1");
        plan.setUserId(userId);
        plan.setData(data);
        return plan;
    }

    private Map<String, Object> activity(double usd, double egp) {
        Map<String, Object> a = new HashMap<>();
        a.put("title", "Existing");
        a.put("cost_usd", usd);
        a.put("cost_egp", egp);
        return a;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> activitiesOf(SavedPlan plan) {
        Map<String, Object> data = (Map<String, Object>) plan.getData();
        List<Map<String, Object>> days = (List<Map<String, Object>>) data.get("days");
        return (List<Map<String, Object>>) days.get(0).get("activities");
    }

    private AddPlaceRequest addReq(Integer dayIndex, String placeId, String time) {
        AddPlaceRequest r = new AddPlaceRequest();
        r.setDayIndex(dayIndex);
        r.setPlaceId(placeId);
        r.setTime(time);
        return r;
    }

    private DeletePlaceRequest delReq(Integer dayIndex, Integer activityIndex) {
        DeletePlaceRequest r = new DeletePlaceRequest();
        r.setDayIndex(dayIndex);
        r.setActivityIndex(activityIndex);
        return r;
    }

    @Test
    void addPlace_appendsMappedActivity() {
        SavedPlan plan = planWithOneDay("u1", List.of(), 100, 4900);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));
        when(landmarkRepository.findById("L1")).thenReturn(Optional.of(landmark("L1")));
        when(savedPlanRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        controller.addPlace("me", "plan1", addReq(0, "L1", "03:00 PM"));

        List<Map<String, Object>> activities = activitiesOf(plan);
        assertThat(activities).hasSize(1);
        Map<String, Object> added = activities.get(0);
        assertThat(added).containsEntry("title", "Pyramids of Giza");
        assertThat(added).containsEntry("description", "Ancient wonder");
        assertThat(added).containsEntry("time", "03:00 PM");
        assertThat(added).containsEntry("category", "attraction");
        assertThat(added).containsEntry("cost_usd", 0);
        assertThat(added.get("lat")).isEqualTo(29.9792);
    }

    @Test
    void addPlace_unknownPlace_throwsNotFound() {
        SavedPlan plan = planWithOneDay("u1", List.of(), 100, 4900);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));
        when(landmarkRepository.findById("nope")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.addPlace("me", "plan1", addReq(0, "nope", "10:00 AM")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND));
    }

    @Test
    void addPlace_dayIndexOutOfRange_throwsBadRequest() {
        SavedPlan plan = planWithOneDay("u1", List.of(), 100, 4900);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));
        when(landmarkRepository.findById("L1")).thenReturn(Optional.of(landmark("L1")));

        assertThatThrownBy(() -> controller.addPlace("me", "plan1", addReq(5, "L1", "10:00 AM")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void addPlace_notOwner_throwsForbidden() {
        SavedPlan plan = planWithOneDay("someoneElse", List.of(), 100, 4900);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));

        assertThatThrownBy(() -> controller.addPlace("me", "plan1", addReq(0, "L1", "10:00 AM")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN));
    }

    @Test
    void deletePlace_removesActivityAndRecomputesTotals() {
        SavedPlan plan = planWithOneDay("u1", List.of(activity(20, 980), activity(15, 735)), 35, 1715);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));
        when(savedPlanRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        controller.deletePlace("me", "plan1", delReq(0, 0));

        List<Map<String, Object>> activities = activitiesOf(plan);
        assertThat(activities).hasSize(1);
        @SuppressWarnings("unchecked")
        Map<String, Object> day = ((List<Map<String, Object>>)
                ((Map<String, Object>) plan.getData()).get("days")).get(0);
        assertThat(((Number) day.get("total_cost_usd")).doubleValue()).isEqualTo(15.0);
        assertThat(((Number) day.get("total_cost_egp")).doubleValue()).isEqualTo(735.0);
    }

    @Test
    void deletePlace_activityIndexOutOfRange_throwsBadRequest() {
        SavedPlan plan = planWithOneDay("u1", List.of(activity(20, 980)), 20, 980);
        when(userService.findByEmail("me")).thenReturn(Optional.of(user("u1")));
        when(savedPlanRepository.findById("plan1")).thenReturn(Optional.of(plan));

        assertThatThrownBy(() -> controller.deletePlace("me", "plan1", delReq(0, 9)))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
    }
}
