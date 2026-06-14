package com.example.jwt_demo.repository;

import com.example.jwt_demo.model.SuggestedPlan;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface SuggestedPlanRepository extends MongoRepository<SuggestedPlan, String> {
    List<SuggestedPlan> findByCategory(String category);
}
