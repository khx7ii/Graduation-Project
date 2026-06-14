package com.example.jwt_demo.service;

import com.example.jwt_demo.dto.AIReply;
import com.example.jwt_demo.exception.AIServiceException;
import com.example.jwt_demo.model.PlanCategory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlanCategoryClassifierTest {

    @Mock
    private AIService aiService;

    @InjectMocks
    private PlanCategoryClassifier classifier;

    private final Object planData = Map.of("title", "Trip", "days", List.of());

    @Test
    void classify_validAnswer_returnsCategory() {
        when(aiService.getReply(any(), isNull(), eq("chat"), any()))
                .thenReturn(new AIReply("chat", "HISTORICAL", null));

        assertThat(classifier.classify(planData)).isEqualTo(PlanCategory.HISTORICAL);
    }

    @Test
    void classify_chattyAnswer_fuzzyMatches() {
        when(aiService.getReply(any(), isNull(), eq("chat"), any()))
                .thenReturn(new AIReply("chat", "This is clearly a BEACH trip", null));

        assertThat(classifier.classify(planData)).isEqualTo(PlanCategory.BEACH);
    }

    @Test
    void classify_unrecognizedAnswer_returnsDefault() {
        when(aiService.getReply(any(), isNull(), eq("chat"), any()))
                .thenReturn(new AIReply("chat", "no idea", null));

        assertThat(classifier.classify(planData)).isEqualTo(PlanCategory.DEFAULT);
    }

    @Test
    void classify_aiThrows_returnsDefault() {
        when(aiService.getReply(any(), isNull(), eq("chat"), any()))
                .thenThrow(new AIServiceException("down"));

        assertThat(classifier.classify(planData)).isEqualTo(PlanCategory.DEFAULT);
    }
}
