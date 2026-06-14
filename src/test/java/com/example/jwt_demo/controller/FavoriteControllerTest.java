package com.example.jwt_demo.controller;

import com.example.jwt_demo.dto.SuggestedPlanCard;
import com.example.jwt_demo.model.SuggestedPlan;
import com.example.jwt_demo.model.User;
import com.example.jwt_demo.repository.SuggestedPlanRepository;
import com.example.jwt_demo.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FavoriteControllerTest {

    @Mock private UserService userService;
    @Mock private SuggestedPlanRepository suggestedPlanRepository;
    @InjectMocks private FavoriteController controller;

    private User user(String id, Set<String> favorites) {
        User u = new User();
        u.setId(id);
        u.setFavoritePlanIds(favorites);
        return u;
    }

    private SuggestedPlan suggested(String id, String name) {
        SuggestedPlan p = new SuggestedPlan();
        p.setId(id);
        p.setName(name);
        p.setSubtitle("sub");
        p.setImageUrl("img");
        return p;
    }

    @Test
    void addFavorite_addsId() {
        User u = user("u1", new HashSet<>());
        when(suggestedPlanRepository.existsById("p1")).thenReturn(true);
        when(userService.findByEmail("me")).thenReturn(Optional.of(u));

        ResponseEntity<Void> response = controller.addFavorite("me", "p1");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userService).save(saved.capture());
        assertThat(saved.getValue().getFavoritePlanIds()).containsExactly("p1");
    }

    @Test
    void addFavorite_idempotent() {
        User u = user("u1", new HashSet<>(Set.of("p1")));
        when(suggestedPlanRepository.existsById("p1")).thenReturn(true);
        when(userService.findByEmail("me")).thenReturn(Optional.of(u));

        controller.addFavorite("me", "p1");

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userService).save(saved.capture());
        assertThat(saved.getValue().getFavoritePlanIds()).containsExactly("p1");
    }

    @Test
    void addFavorite_unknownPlan_throwsNotFound() {
        when(suggestedPlanRepository.existsById("nope")).thenReturn(false);

        assertThatThrownBy(() -> controller.addFavorite("me", "nope"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND));
        verify(userService, never()).save(any());
    }

    @Test
    void removeFavorite_removesId() {
        User u = user("u1", new HashSet<>(Set.of("p1", "p2")));
        when(userService.findByEmail("me")).thenReturn(Optional.of(u));

        ResponseEntity<Void> response = controller.removeFavorite("me", "p1");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userService).save(saved.capture());
        assertThat(saved.getValue().getFavoritePlanIds()).containsExactly("p2");
    }

    @Test
    void myFavorites_returnsCardsAndSkipsMissingIds() {
        User u = user("u1", new HashSet<>(Set.of("p1", "deleted")));
        when(userService.findByEmail("me")).thenReturn(Optional.of(u));
        // repository only returns the still-existing plan, dropping "deleted"
        when(suggestedPlanRepository.findAllById(u.getFavoritePlanIds()))
                .thenReturn(List.of(suggested("p1", "Nile Cruise")));

        ResponseEntity<List<SuggestedPlanCard>> response = controller.myFavorites("me");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).getId()).isEqualTo("p1");
        assertThat(response.getBody().get(0).getName()).isEqualTo("Nile Cruise");
    }

    @Test
    void favorites_nullSet_handledGracefully() {
        User u = user("u1", null);
        when(suggestedPlanRepository.existsById("p1")).thenReturn(true);
        when(userService.findByEmail("me")).thenReturn(Optional.of(u));

        controller.addFavorite("me", "p1");

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userService).save(saved.capture());
        assertThat(saved.getValue().getFavoritePlanIds()).containsExactly("p1");
    }
}
