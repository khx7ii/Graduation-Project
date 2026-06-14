package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.SuggestedPlanCard;
import com.example.jwt_demo.model.SuggestedPlan;
import com.example.jwt_demo.repository.LandmarkRepository;
import com.example.jwt_demo.repository.SuggestedPlanRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HomeControllerTest {

    @Mock
    private LandmarkRepository landmarkRepository;
    @Mock
    private SuggestedPlanRepository suggestedPlanRepository;
    @InjectMocks
    private HomeController controller;

    @Test
    void categories_returnsAllSixFixedCategories() {
        ResponseEntity<List<Map<String, String>>> response = controller.categories();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(6);
        assertThat(response.getBody()).anySatisfy(c -> {
            assertThat(c.get("id")).isEqualTo("NILE_CRUISE");
            assertThat(c.get("label")).isEqualTo("Nile Cruise");
        });
    }

    @Test
    void plansByCategory_unknownCategory_throwsBadRequest() {
        assertThatThrownBy(() -> controller.plansByCategory("space"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void plansByCategory_valid_returnsFilteredCards() {
        SuggestedPlan plan = new SuggestedPlan();
        plan.setId("p1");
        plan.setName("Red Sea Diving Trip");
        plan.setSubtitle("4 days in Hurghada");
        plan.setImageUrl("img");
        plan.setCategory("BEACH");
        when(suggestedPlanRepository.findByCategory("BEACH")).thenReturn(List.of(plan));

        ResponseEntity<List<SuggestedPlanCard>> response = controller.plansByCategory("beach");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).getId()).isEqualTo("p1");
        assertThat(response.getBody().get(0).getName()).isEqualTo("Red Sea Diving Trip");
    }

    @Test
    void plansByCategory_validButEmpty_returnsEmptyList() {
        when(suggestedPlanRepository.findByCategory("DESERT")).thenReturn(List.of());

        ResponseEntity<List<SuggestedPlanCard>> response = controller.plansByCategory("DESERT");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEmpty();
    }
}
