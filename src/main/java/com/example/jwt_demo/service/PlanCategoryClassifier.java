package com.example.jwt_demo.service;

import com.example.jwt_demo.dto.AIReply;
import com.example.jwt_demo.model.PlanCategory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class PlanCategoryClassifier {

    private static final Logger log = LoggerFactory.getLogger(PlanCategoryClassifier.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AIService aiService;

    public PlanCategoryClassifier(AIService aiService) {
        this.aiService = aiService;
    }

    /**
     * Ask the existing chat model to pick one of our fixed categories for a plan.
     * Never throws: any failure or unrecognized answer falls back to {@link PlanCategory#DEFAULT}.
     */
    public PlanCategory classify(Object planData) {
        try {
            String planJson = MAPPER.writeValueAsString(planData);
            String options = Arrays.stream(PlanCategory.values())
                    .map(Enum::name)
                    .collect(Collectors.joining(", "));
            String prompt = "Here is a travel plan as JSON. Choose the single best category for it from this "
                    + "exact list: " + options + ". Reply with one value only, nothing else.";
            List<Map<String, String>> history = List.of(Map.of("role", "Soli", "content", planJson));

            AIReply reply = aiService.getReply(prompt, null, "chat", history);
            PlanCategory category = PlanCategory.fromText(reply.getContent());
            log.info("Classified plan as category {}", category);
            return category;
        } catch (Exception e) {
            log.warn("Plan classification failed, defaulting to {}: {}", PlanCategory.DEFAULT, e.getMessage());
            return PlanCategory.DEFAULT;
        }
    }
}
