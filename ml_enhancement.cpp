// Machine Learning Enhancement for randomness_breaker.cpp
// Bu kodu mevcut class'ın private bölümüne ekleyin:

private:
    // Machine Learning System
    std::vector<std::pair<uint16_t, uint16_t>> training_data; // source -> target pairs
    std::map<uint16_t, std::vector<uint16_t>> successful_mappings; // target -> successful sources
    std::map<int32_t, std::vector<uint16_t>> distance_mappings; // distance -> successful sources
    std::vector<uint16_t> golden_sources; // En başarılı source port'lar
    double learning_rate = 0.1;
    
// Bu fonksiyonları class içine ekleyin:

uint16_t machine_learning_source_prediction(uint16_t target_port) {
    if (training_data.size() < 5) {
        return 30000 + (target_port % 10000); // Fallback
    }
    
    // Simple neural network approach
    double sum_src = 0, sum_tgt = 0, sum_src_tgt = 0, sum_src2 = 0;
    int n = training_data.size();
    
    for (const auto& pair : training_data) {
        sum_src += pair.first;
        sum_tgt += pair.second;
        sum_src_tgt += pair.first * pair.second;
        sum_src2 += pair.first * pair.first;
    }
    
    // Linear regression coefficients
    double slope = (n * sum_src_tgt - sum_src * sum_tgt) / (n * sum_src2 - sum_src * sum_src);
    double intercept = (sum_tgt - slope * sum_src) / n;
    
    // Reverse prediction: source = (target - intercept) / slope
    uint16_t predicted_source;
    if (std::abs(slope) > 0.001) {
        double raw = (static_cast<double>(target_port) - intercept) / slope;
        predicted_source = static_cast<uint16_t>(std::max(1024.0, std::min(65535.0, raw)));
    } else {
        predicted_source = static_cast<uint16_t>(sum_src / n);
    }
    
    return predicted_source;
}

void learn_from_attempt(uint16_t source_port, uint16_t target_port, uint16_t achieved_port) {
    // Add to training data
    training_data.push_back({source_port, achieved_port});
    
    // Learn successful mappings
    if (achieved_port == target_port) {
        successful_mappings[target_port].push_back(source_port);
        golden_sources.push_back(source_port);
    }
    
    // Learn distance patterns
    int32_t distance = static_cast<int32_t>(achieved_port) - static_cast<int32_t>(target_port);
    if (std::abs(distance) <= 50) { // Only learn from close attempts
        distance_mappings[distance].push_back(source_port);
    }
    
    // Keep training data manageable (last 100 entries)
    if (training_data.size() > 100) {
        training_data.erase(training_data.begin());
    }
}

uint16_t get_learned_source_for_target(uint16_t target_port) {
    // Check exact matches first
    if (successful_mappings.find(target_port) != successful_mappings.end() && 
        !successful_mappings[target_port].empty()) {
        return successful_mappings[target_port].back(); // Most recent successful
    }
    
    // Check distance patterns
    for (int32_t dist = 0; dist <= 10; dist++) {
        if (distance_mappings.find(dist) != distance_mappings.end() && 
            !distance_mappings[dist].empty()) {
            return distance_mappings[dist].back();
        }
        if (dist > 0 && distance_mappings.find(-dist) != distance_mappings.end() && 
            !distance_mappings[-dist].empty()) {
            return distance_mappings[-dist].back();
        }
    }
    
    // Use machine learning prediction
    return machine_learning_source_prediction(target_port);
}

bool execute_ml_enhanced_targeting(uint16_t target_port) {
    std::cout << "\n🧠 MACHINE LEARNING ENHANCED TARGETING" << std::endl;
    std::cout << "=" << std::string(50, '=') << std::endl;
    std::cout << "🎯 Target: " << target_port << std::endl;
    std::cout << "📚 Training data: " << training_data.size() << " samples" << std::endl;
    
    // Phase 1: Try learned patterns (if any)
    uint16_t learned_source = get_learned_source_for_target(target_port);
    std::cout << "🔍 Learned source prediction: " << learned_source << std::endl;
    
    uint16_t result = execute_single_targeted_request(learned_source);
    if (result == target_port) {
        std::cout << "🎉 MACHINE LEARNING HIT!" << std::endl;
        return true;
    }
    
    int32_t gap = std::abs(static_cast<int32_t>(target_port) - static_cast<int32_t>(result));
    std::cout << "📊 ML result: " << result << " (gap: " << gap << ")" << std::endl;
    learn_from_attempt(learned_source, target_port, result);
    
    // Phase 2: ML-guided fine-tuning
    if (gap <= 100) {
        std::cout << "🔍 ML-guided fine-tuning around learned source..." << std::endl;
        
        for (int offset = -50; offset <= 50; offset += 5) {
            uint16_t test_source = learned_source + offset;
            if (test_source < 1024 || test_source > 65535) continue;
            
            uint16_t test_result = execute_single_targeted_request(test_source);
            learn_from_attempt(test_source, target_port, test_result);
            
            if (test_result == target_port) {
                std::cout << "🎯 ML FINE-TUNING HIT! (offset: " << offset << ")" << std::endl;
                return true;
            }
            
            int32_t test_gap = std::abs(static_cast<int32_t>(target_port) - static_cast<int32_t>(test_result));
            if (test_gap < gap) {
                std::cout << "   ✅ ML Fine " << offset << ": " << test_result 
                          << " (improved gap: " << test_gap << ")" << std::endl;
                gap = test_gap;
                
                // Deeper search around better results
                if (test_gap <= 10) {
                    for (int deep = -5; deep <= 5; deep++) {
                        uint16_t deep_source = test_source + deep;
                        uint16_t deep_result = execute_single_targeted_request(deep_source);
                        learn_from_attempt(deep_source, target_port, deep_result);
                        
                        if (deep_result == target_port) {
                            std::cout << "     🎯 ML DEEP HIT!" << std::endl;
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    std::cout << "📊 ML Enhanced targeting completed. Best gap: " << gap << std::endl;
    return false;
}

// collect_stun_responses_multi_socket fonksiyonuna bu satırı ekleyin:
// (measurement eklendikten sonra)
training_data.push_back({measurement.source_port, measurement.assigned_port});

// execute_distance_specific_attack fonksiyonunda her attempt'ten sonra:
// learn_from_attempt(src_port, target_port, achieved_port);

// execute_iterative_exact_targeting başında ML targeting deneyin:
// if (execute_ml_enhanced_targeting(target_port)) {
//     return true;
// }
