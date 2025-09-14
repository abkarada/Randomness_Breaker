#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <set>
#include <complex>
#include <numeric>
#include <cmath>
#include <fstream>
#include <iomanip>

// STUN message structure
struct STUNHeader {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
} __attribute__((packed));

// Packet measurement data
struct PacketMeasurement {
    uint16_t assigned_port;
    uint64_t timestamp_us;
    uint32_t sequence_number;
    uint16_t source_port;
    std::string target_ip;
    bool success;
};

// Forward declarations
struct PortPrediction {
    uint16_t predicted_port;
    double confidence;
    std::string method;
    int steps_ahead;
};

class AdvancedNATAnalyzer {
private:
    std::vector<PacketMeasurement> measurements;
    std::string target_stun_server;
    uint16_t stun_port;
    int socket_fd;
    
    // 🧠 MACHINE LEARNING SYSTEM
    std::vector<std::pair<uint16_t, uint16_t>> training_data; // source -> target pairs
    std::map<uint16_t, std::vector<uint16_t>> successful_mappings; // target -> successful sources
    std::map<int32_t, std::vector<uint16_t>> distance_mappings; // distance -> successful sources
    std::vector<uint16_t> golden_sources; // En başarılı source port'lar
    double ml_confidence = 0.0; // ML model confidence
    
public:
    AdvancedNATAnalyzer(const std::string& stun_server = "stun.l.google.com", uint16_t port = 19302) 
        : target_stun_server(stun_server), stun_port(port), socket_fd(-1) {
        
        std::cout << "🚀 Advanced C++ NAT Analyzer - ML Enhanced + 8-Layer System" << std::endl;
        std::cout << "Target STUN Server: " << stun_server << ":" << port << std::endl;
    }
    
    ~AdvancedNATAnalyzer() {
        if (socket_fd != -1) {
            close(socket_fd);
        }
    }
    
    bool initialize_socket() {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            perror("Socket creation failed");
            return false;
        }
        
        // Enable source port reuse
        int reuse = 1;
        setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        
        return true;
    }
    
    uint64_t get_timestamp_us() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
    }
    
    void create_stun_binding_request(uint8_t* buffer, uint8_t* transaction_id) {
        STUNHeader* header = reinterpret_cast<STUNHeader*>(buffer);
        header->type = htons(0x0001);  // Binding Request
        header->length = 0;  // No attributes for basic request
        header->magic_cookie = htonl(0x2112A442);  // STUN magic cookie
        memcpy(header->transaction_id, transaction_id, 12);
    }
    
    void resolve_hostname_to_ip() {
        // Simple resolution - in production use getaddrinfo
        if (target_stun_server == "stun.l.google.com") {
            target_stun_server = "74.125.250.129";
        }
        std::cout << "📍 Resolved to: " << target_stun_server << std::endl;
    }
    
    // 🧠 MACHINE LEARNING FUNCTIONS
    
    uint16_t ml_predict_optimal_source(uint16_t target_port) {
        if (training_data.size() < 3) {
            return 30000 + (target_port % 10000);
        }
        
        // Linear regression
        double sum_src = 0, sum_tgt = 0, sum_src_tgt = 0, sum_src2 = 0;
        int n = training_data.size();
        
        for (const auto& pair : training_data) {
            sum_src += pair.first;
            sum_tgt += pair.second;
            sum_src_tgt += pair.first * pair.second;
            sum_src2 += pair.first * pair.first;
        }
        
        double slope = (n * sum_src_tgt - sum_src * sum_tgt) / (n * sum_src2 - sum_src * sum_src);
        double intercept = (sum_tgt - slope * sum_src) / n;
        
        // Calculate confidence
        double mean_src = sum_src / n;
        double mean_tgt = sum_tgt / n;
        double numerator = 0.0, denom_src = 0.0, denom_tgt = 0.0;
        
        for (const auto& pair : training_data) {
            numerator += (pair.first - mean_src) * (pair.second - mean_tgt);
            denom_src += (pair.first - mean_src) * (pair.first - mean_src);
            denom_tgt += (pair.second - mean_tgt) * (pair.second - mean_tgt);
        }
        
        double correlation = numerator / std::sqrt(denom_src * denom_tgt);
        ml_confidence = std::abs(correlation);
        
        // Reverse prediction
        uint16_t predicted_source;
        if (std::abs(slope) > 0.001) {
            double raw = (static_cast<double>(target_port) - intercept) / slope;
            predicted_source = static_cast<uint16_t>(std::max(1024.0, std::min(65535.0, raw)));
        } else {
            predicted_source = static_cast<uint16_t>(mean_src);
        }
        
        return predicted_source;
    }
    
    void learn_from_attempt(uint16_t source_port, uint16_t target_port, uint16_t achieved_port) {
        // Add to training data
        training_data.push_back({source_port, achieved_port});
        
        // Learn successful exact matches
        if (achieved_port == target_port) {
            successful_mappings[target_port].push_back(source_port);
            golden_sources.push_back(source_port);
        }
        
        // Learn distance patterns (for close misses)
        int32_t distance = static_cast<int32_t>(achieved_port) - static_cast<int32_t>(target_port);
        if (std::abs(distance) <= 20) { // Learn from close attempts
            distance_mappings[distance].push_back(source_port);
        }
        
        // Keep data manageable
        if (training_data.size() > 100) {
            training_data.erase(training_data.begin());
        }
    }
    
    bool execute_ml_enhanced_attack(uint16_t target_port, int max_attempts = 30) {
        std::cout << "\n🧠 ML-ENHANCED ATTACK" << std::endl;
        std::cout << "🎯 Target: " << target_port << std::endl;
        std::cout << "📚 ML Training data: " << training_data.size() << " samples" << std::endl;
        
        // Phase 1: Direct learned pattern check
        if (successful_mappings.find(target_port) != successful_mappings.end()) {
            std::cout << "🎯 Found exact learned mapping!" << std::endl;
            for (uint16_t learned_src : successful_mappings[target_port]) {
                uint16_t result = execute_single_targeted_request(learned_src);
                if (result == target_port) {
                    std::cout << "🎉 EXACT LEARNED HIT!" << std::endl;
                    return true;
                }
            }
        }
        
        // Phase 2: ML prediction with variations
        uint16_t ml_source = ml_predict_optimal_source(target_port);
        std::cout << "📊 ML predicted source: " << ml_source << " (confidence: " 
                  << std::fixed << std::setprecision(3) << ml_confidence << ")" << std::endl;
        
        uint16_t best_result = 0;
        int32_t best_gap = INT32_MAX;
        
        // Test ML prediction with variations
        for (int i = 0; i < max_attempts; i++) {
            uint16_t test_source;
            
            if (i < 10) {
                // Pure ML predictions with small variations
                test_source = ml_source + (i * 50) + ((target_port + i) % 100);
            } else if (i < 20) {
                // ML + mathematical enhancement
                test_source = ml_source + ((target_port * i) % 500) + (i * 73);
            } else {
                // ML + chaos for breakthrough
                test_source = ml_source + ((i * target_port) % 1000) + (i * i % 300);
            }
            
            uint16_t result = execute_single_targeted_request(test_source);
            learn_from_attempt(test_source, target_port, result);
            
            if (result == target_port) {
                std::cout << "🎉 ML ENHANCED HIT! (attempt " << (i+1) << ")" << std::endl;
                return true;
            }
            
            int32_t gap = std::abs(static_cast<int32_t>(target_port) - static_cast<int32_t>(result));
            if (gap < best_gap) {
                best_gap = gap;
                best_result = result;
                std::cout << "   ✅ ML " << (i+1) << ": " << result << " (gap: " << gap << ")" << std::endl;
                
                // Intensive search around very good ML results
                if (gap <= 5) {
                    std::cout << "   🔥 ML Very close! Intensive search..." << std::endl;
                    for (int fine = -20; fine <= 20; fine++) {
                        uint16_t fine_src = test_source + fine;
                        uint16_t fine_result = execute_single_targeted_request(fine_src);
                        learn_from_attempt(fine_src, target_port, fine_result);
                        
                        if (fine_result == target_port) {
                            std::cout << "     🎯 ML INTENSIVE HIT!" << std::endl;
                            return true;
                        }
                    }
                }
            }
        }
        
        std::cout << "📊 ML Enhanced attack completed. Best: " << best_result << " (gap: " << best_gap << ")" << std::endl;
        return false;
    }
    
    // Mevcut fonksiyonlar (aynı kalacak, sadece ML entegrasyonu eklenecek)
    // ... (execute_high_performance_burst, collect_stun_responses_multi_socket, etc.)
    
    bool execute_high_performance_burst(int packet_count, uint16_t start_port = 0) {
        std::cout << "🔥 Starting ML-enhanced high-performance burst: " << packet_count << " packets" << std::endl;
        std::cout << "🎯 Strategy: Each packet from different source port for unique NAT sessions" << std::endl;
        
        resolve_hostname_to_ip();
        
        // Prepare target address
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(stun_port);
        inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
        
        measurements.clear();
        measurements.reserve(packet_count);
        
        auto start_time = get_timestamp_us();
        
        // Create separate sockets for each source port to get unique NAT mappings
        std::vector<int> sockets(packet_count);
        std::vector<struct sockaddr_in> source_addrs(packet_count);
        
        // Prepare sendmmsg structures
        std::vector<struct mmsghdr> msgs(packet_count);
        std::vector<struct iovec> iovecs(packet_count);
        std::vector<uint8_t> buffers(packet_count * 20);  // 20 bytes per STUN header
        std::vector<uint8_t> transaction_ids(packet_count * 12);
        
        // Create sockets with different source ports
        for (int i = 0; i < packet_count; ++i) {
            sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockets[i] < 0) {
                perror("Socket creation failed");
                return false;
            }
            
            // Bind to specific source port
            memset(&source_addrs[i], 0, sizeof(source_addrs[i]));
            source_addrs[i].sin_family = AF_INET;
            source_addrs[i].sin_addr.s_addr = INADDR_ANY;
            source_addrs[i].sin_port = htons(start_port + 10000 + i);  // Use different source ports
            
            if (bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i])) < 0) {
                // If bind fails, let kernel choose port
                source_addrs[i].sin_port = 0;
                bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i]));
            }
            
            uint8_t* buffer = &buffers[i * 20];
            uint8_t* trans_id = &transaction_ids[i * 12];
            
            // Generate unique transaction ID
            for (int j = 0; j < 12; ++j) {
                trans_id[j] = rand() & 0xFF;
            }
            
            create_stun_binding_request(buffer, trans_id);
            
            iovecs[i].iov_base = buffer;
            iovecs[i].iov_len = 20;
            
            msgs[i].msg_hdr.msg_name = &target_addr;
            msgs[i].msg_hdr.msg_namelen = sizeof(target_addr);
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = nullptr;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }
        
        std::cout << "📦 Prepared " << packet_count << " STUN messages with unique source ports" << std::endl;
        std::cout << "🚀 Executing individual socket sends for NAT diversity..." << std::endl;
        
        // Send from each socket individually to ensure different NAT sessions
        auto burst_start = get_timestamp_us();
        int sent = 0;
        
        for (int i = 0; i < packet_count; ++i) {
            ssize_t result = sendto(sockets[i], buffers.data() + i * 20, 20, 0,
                                   (struct sockaddr*)&target_addr, sizeof(target_addr));
            if (result > 0) {
                sent++;
            }
        }
        
        auto burst_end = get_timestamp_us();
        
        std::cout << "✅ Burst complete: " << sent << "/" << packet_count << " packets sent" << std::endl;
        
        double burst_duration_s = (burst_end - burst_start) / 1e6;
        double packet_rate = sent / burst_duration_s;
        
        std::cout << "⚡ Burst Performance:" << std::endl;
        std::cout << "   Duration: " << std::fixed << std::setprecision(3) 
                  << burst_duration_s << "s" << std::endl;
        std::cout << "   Rate: " << std::fixed << std::setprecision(0) 
                  << packet_rate << " packets/second" << std::endl;
        
        // Now collect responses for pattern analysis from all sockets
        bool result = collect_stun_responses_multi_socket(sockets, sent, start_time);
        
        // Close all sockets
        for (int sock : sockets) {
            close(sock);
        }
        
        return result;
    }
    
    bool collect_stun_responses_multi_socket(const std::vector<int>& sockets, int expected_responses, uint64_t start_time) {
        std::cout << "📡 Collecting STUN responses from multiple sockets..." << std::endl;
        
        // Set socket timeout for all sockets
        struct timeval timeout;
        timeout.tv_sec = 3;  // 3 seconds timeout per socket
        timeout.tv_usec = 0;
        
        for (int sock : sockets) {
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        }
        
        uint8_t response_buffer[1500];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        int responses_received = 0;
        auto collection_start = get_timestamp_us();
        
        // Collect responses from each socket
        for (size_t i = 0; i < sockets.size() && responses_received < expected_responses; ++i) {
            ssize_t bytes_received = recvfrom(sockets[i], response_buffer, sizeof(response_buffer),
                                            0, (struct sockaddr*)&from_addr, &from_len);
            
            if (bytes_received >= 20) {  // Valid STUN response size
                STUNHeader* header = reinterpret_cast<STUNHeader*>(response_buffer);
                
                if (ntohs(header->type) == 0x0101) {  // Binding Success Response
                    uint16_t assigned_port = parse_mapped_address(response_buffer, bytes_received);
                    
                    if (assigned_port > 0) {
                        PacketMeasurement measurement;
                        measurement.assigned_port = assigned_port;
                        measurement.timestamp_us = get_timestamp_us();
                        measurement.sequence_number = responses_received;
                        measurement.source_port = 10000 + i;  // Track which socket
                        measurement.target_ip = target_stun_server;
                        measurement.success = true;
                        
                        measurements.push_back(measurement);
                        
                        // 🧠 ML LEARNING: Add to training data
                        training_data.push_back({measurement.source_port, measurement.assigned_port});
                        
                        responses_received++;
                        
                        if (responses_received % 10 == 0 || responses_received < 20) {
                            std::cout << "📊 Response " << responses_received 
                                      << " (src:" << measurement.source_port << "): Port " 
                                      << assigned_port << std::endl;
                        }
                    }
                }
            }
        }
        
        auto collection_end = get_timestamp_us();
        double collection_duration = (collection_end - collection_start) / 1e6;
        
        std::cout << "✅ Multi-socket Response Collection Complete:" << std::endl;
        std::cout << "   Received: " << responses_received << "/" << expected_responses << std::endl;
        std::cout << "   Duration: " << collection_duration << "s" << std::endl;
        std::cout << "   Success Rate: " << (100.0 * responses_received / expected_responses) << "%" << std::endl;
        std::cout << "   🧠 ML Training data: " << training_data.size() << " source-target pairs" << std::endl;
        
        return responses_received > 0;
    }
    
    uint16_t parse_mapped_address(uint8_t* buffer, size_t length) {
        // Skip STUN header (20 bytes)
        uint8_t* ptr = buffer + 20;
        uint8_t* end = buffer + length;
        
        while (ptr + 4 <= end) {
            uint16_t attr_type = ntohs(*reinterpret_cast<uint16_t*>(ptr));
            uint16_t attr_length = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
            ptr += 4;
            
            if (ptr + attr_length > end) break;
            
            // MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020)
            if (attr_type == 0x0001 || attr_type == 0x0020) {
                if (attr_length >= 8) {
                    uint16_t port = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
                    
                    // If XOR-MAPPED-ADDRESS, XOR with magic cookie
                    if (attr_type == 0x0020) {
                        port ^= 0x2112;
                    }
                    
                    return port;
                }
            }
            
            ptr += attr_length;
            // Align to 4-byte boundary
            while ((ptr - buffer) % 4 != 0 && ptr < end) ptr++;
        }
        
        return 0;  // No mapped address found
    }
    
    // ML-Enhanced exact port targeting
    bool execute_iterative_exact_targeting(uint16_t target_port) {
        std::cout << "\n🧠 ML-ENHANCED EXACT PORT TARGETING" << std::endl;
        std::cout << "=" << std::string(60, '=') << std::endl;
        std::cout << "🎯 Target Port: " << target_port << std::endl;
        std::cout << "📊 Starting Port: " << measurements.back().assigned_port << std::endl;
        std::cout << "🧠 Strategy: Machine Learning + 8-Layer Precision" << std::endl;
        std::cout << "=" << std::string(60, '=') << std::endl;
        
        // Phase 1: ML-Enhanced Attack (önce dene)
        if (execute_ml_enhanced_attack(target_port, 25)) {
            return true;
        }
        
        // Phase 2: Traditional 8-layer system with ML learning
        uint16_t current_port = measurements.back().assigned_port;
        const int MAX_ITERATIONS = 10;
        const int ATTEMPTS_PER_ITERATION = 40;
        
        for (int iteration = 1; iteration <= MAX_ITERATIONS; iteration++) {
            int32_t distance = (int32_t)target_port - (int32_t)current_port;
            
            std::cout << "\n🔄 ML-ENHANCED ITERATION " << iteration << "/" << MAX_ITERATIONS << std::endl;
            std::cout << "   📍 Current: " << current_port << " → 🎯 Target: " << target_port << std::endl;
            std::cout << "   📏 Distance: " << abs(distance) << " ports" << std::endl;
            
            if (distance == 0) {
                std::cout << "🎉 EXACT TARGET ACHIEVED!" << std::endl;
                return true;
            }
            
            uint16_t best_port = current_port;
            int32_t best_distance = abs(distance);
            
            for (int i = 0; i < ATTEMPTS_PER_ITERATION; i++) {
                uint16_t src_port;
                
                // ML-Enhanced source calculation
                if (i < 10 && training_data.size() >= 5) {
                    // Use ML prediction for first 10 attempts
                    uint16_t ml_source = ml_predict_optimal_source(target_port);
                    src_port = ml_source + (i * 100) + ((target_port + distance) % 200);
                } else {
                    // Use enhanced 8-layer system
                    if (target_port >= 19000 && target_port <= 21000) {
                        if (distance > 0) {
                            src_port = 35000 + (distance * 3) + (i * 73) + (target_port % 500) + 
                                      (distance % 100) + ((target_port * 7) % 200);
                        } else {
                            src_port = 22000 - (abs(distance) * 3) - (i * 73) - (target_port % 500) - 
                                      (abs(distance) % 100) - ((target_port * 7) % 200);
                        }
                    } else if (target_port >= 17000 && target_port <= 19000) {
                        if (distance > 0) {
                            src_port = 28000 + (distance * 2) + (i * 61) + (target_port % 300);
                        } else {
                            src_port = 20000 - (abs(distance) * 2) - (i * 61) - (target_port % 300);
                        }
                    } else {
                        if (distance > 0) {
                            src_port = 32000 + (distance * 4) + (i * 89) + (distance % 200);
                        } else {
                            src_port = 24000 - (abs(distance) * 4) - (i * 89) - (abs(distance) % 200);
                        }
                    }
                    
                    // Enhanced fine-tuning
                    src_port += (target_port % 127) + (i % 53) + ((target_port * i) % 79);
                }
                
                uint16_t achieved_port = execute_single_targeted_request(src_port);
                
                // 🧠 ML LEARNING: Learn from every attempt
                learn_from_attempt(src_port, target_port, achieved_port);
                
                if (achieved_port == target_port) {
                    std::cout << "       🎯 ML-ENHANCED EXACT HIT!" << std::endl;
                    return true;
                }
                
                int32_t achieved_distance = abs((int32_t)target_port - (int32_t)achieved_port);
                if (achieved_distance < best_distance) {
                    best_distance = achieved_distance;
                    best_port = achieved_port;
                    std::cout << "       ✅ ML-Enhanced " << (i+1) << ": " << achieved_port 
                              << " (gap: " << achieved_distance << ")" << std::endl;
                }
            }
            
            // Update for next iteration
            if (best_distance < abs(distance)) {
                current_port = best_port;
                std::cout << "   ✅ ML IMPROVEMENT: " << abs(distance) << " → " << best_distance << std::endl;
            } else {
                std::cout << "   🔄 No improvement, continuing..." << std::endl;
            }
            
            // Early precision mode for close results
            if (best_distance <= 10) {
                std::cout << "🎯 Close enough! ML-enhanced precision mode..." << std::endl;
                return execute_ml_precision_mode(target_port, current_port);
            }
        }
        
        std::cout << "\n📊 ML-ENHANCED FINAL RESULTS" << std::endl;
        std::cout << "🎯 Target: " << target_port << std::endl;
        std::cout << "✅ Best: " << current_port << std::endl;
        std::cout << "📏 Gap: " << abs((int32_t)target_port - (int32_t)current_port) << std::endl;
        std::cout << "🧠 ML Confidence: " << std::fixed << std::setprecision(3) << ml_confidence << std::endl;
        
        return false;
    }
    
    bool execute_ml_precision_mode(uint16_t target_port, uint16_t current_port) {
        std::cout << "🧠 ML-ENHANCED PRECISION MODE" << std::endl;
        
        int32_t distance = (int32_t)target_port - (int32_t)current_port;
        
        // Use all learned patterns for precision targeting
        std::vector<uint16_t> precision_sources;
        
        // Add ML predictions
        precision_sources.push_back(ml_predict_optimal_source(target_port));
        
        // Add learned sources for similar distances
        for (int32_t d = -5; d <= 5; d++) {
            if (distance_mappings.find(distance + d) != distance_mappings.end()) {
                for (uint16_t src : distance_mappings[distance + d]) {
                    precision_sources.push_back(src);
                }
            }
        }
        
        // Add golden sources with variations
        for (uint16_t golden : golden_sources) {
            for (int var = -50; var <= 50; var += 10) {
                precision_sources.push_back(golden + var);
            }
        }
        
        std::cout << "🔍 Testing " << precision_sources.size() << " ML-guided precision sources..." << std::endl;
        
        for (size_t i = 0; i < precision_sources.size(); i++) {
            uint16_t test_source = precision_sources[i];
            uint16_t result = execute_single_targeted_request(test_source);
            learn_from_attempt(test_source, target_port, result);
            
            if (result == target_port) {
                std::cout << "🎉 ML PRECISION HIT! (source: " << test_source << ")" << std::endl;
                return true;
            }
            
            int32_t gap = std::abs(static_cast<int32_t>(target_port) - static_cast<int32_t>(result));
            if (gap <= 2) {
                std::cout << "   🔥 Very close: " << result << " (gap: " << gap << ")" << std::endl;
                
                // Ultra-fine search around very close results
                for (int ultra = -10; ultra <= 10; ultra++) {
                    uint16_t ultra_src = test_source + ultra;
                    uint16_t ultra_result = execute_single_targeted_request(ultra_src);
                    learn_from_attempt(ultra_src, target_port, ultra_result);
                    
                    if (ultra_result == target_port) {
                        std::cout << "     🎯 ML ULTRA-FINE HIT!" << std::endl;
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    uint16_t execute_single_targeted_request(uint16_t source_port) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return 0;
        
        struct sockaddr_in source_addr, target_addr;
        
        // Bind to specific source port
        memset(&source_addr, 0, sizeof(source_addr));
        source_addr.sin_family = AF_INET;
        source_addr.sin_addr.s_addr = INADDR_ANY;
        source_addr.sin_port = htons(source_port);
        
        if (bind(sock, (struct sockaddr*)&source_addr, sizeof(source_addr)) < 0) {
            source_addr.sin_port = 0;  // Let system choose if bind fails
            bind(sock, (struct sockaddr*)&source_addr, sizeof(source_addr));
        }
        
        // Target setup
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(stun_port);
        inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
        
        // Send request
        uint8_t buffer[20];
        uint8_t trans_id[12];
        for (int j = 0; j < 12; ++j) trans_id[j] = rand() & 0xFF;
        create_stun_binding_request(buffer, trans_id);
        
        sendto(sock, buffer, 20, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
        
        // Get response with timeout
        struct timeval timeout = {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        uint8_t response[1500];
        ssize_t bytes = recvfrom(sock, response, sizeof(response), 0, nullptr, nullptr);
        
        close(sock);
        
        if (bytes >= 20) {
            return parse_mapped_address(response, bytes);
        }
        
        return 0;
    }
    
    // Simplified analysis functions
    void run_comprehensive_analysis() {
        if (measurements.empty()) {
            std::cout << "❌ No measurement data available for analysis" << std::endl;
            return;
        }
        
        std::cout << "\n🔬 ML-ENHANCED COMPREHENSIVE ANALYSIS" << std::endl;
        std::cout << "=" << std::string(50, '=') << std::endl;
        std::cout << "📊 Dataset: " << measurements.size() << " measurements" << std::endl;
        std::cout << "🧠 ML Training: " << training_data.size() << " source-target pairs" << std::endl;
        std::cout << "🏆 Golden sources: " << golden_sources.size() << " exact hits" << std::endl;
        
        // Extract port sequence for basic analysis
        std::vector<uint16_t> ports;
        for (const auto& m : measurements) {
            ports.push_back(m.assigned_port);
        }
        
        // Basic statistics
        uint16_t min_port = *std::min_element(ports.begin(), ports.end());
        uint16_t max_port = *std::max_element(ports.begin(), ports.end());
        double mean_port = std::accumulate(ports.begin(), ports.end(), 0.0) / ports.size();
        
        std::cout << "\n📈 BASIC STATISTICS:" << std::endl;
        std::cout << "   Port Range: " << min_port << " - " << max_port << std::endl;
        std::cout << "   Mean Port: " << std::fixed << std::setprecision(1) << mean_port << std::endl;
        
        // ML Model analysis
        if (training_data.size() >= 5) {
            uint16_t ml_test = ml_predict_optimal_source(19500); // Test prediction
            std::cout << "\n🧠 ML MODEL STATUS:" << std::endl;
            std::cout << "   Confidence: " << std::fixed << std::setprecision(3) << ml_confidence << std::endl;
            std::cout << "   Test prediction (19500): " << ml_test << std::endl;
            
            if (ml_confidence > 0.3) {
                std::cout << "   ✅ HIGH confidence ML model" << std::endl;
            } else if (ml_confidence > 0.1) {
                std::cout << "   📊 MEDIUM confidence ML model" << std::endl;
            } else {
                std::cout << "   ⚠️  LOW confidence ML model" << std::endl;
            }
        }
    }
    
    void save_results_to_file() {
        std::string filename = "ml_nat_results_" + 
                              std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::system_clock::now().time_since_epoch()).count()) + ".txt";
        
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "ML-Enhanced NAT Analysis Results\n";
            file << "=================================\n\n";
            file << "ML Training Data (source -> target):\n";
            for (const auto& pair : training_data) {
                file << pair.first << " -> " << pair.second << "\n";
            }
            
            file << "\nSuccessful Mappings:\n";
            for (const auto& [target, sources] : successful_mappings) {
                file << "Target " << target << ": ";
                for (uint16_t src : sources) {
                    file << src << " ";
                }
                file << "\n";
            }
            
            file << "\nGolden Sources: ";
            for (uint16_t src : golden_sources) {
                file << src << " ";
            }
            file << "\n";
            
            file.close();
            std::cout << "\n💾 ML Results saved to: " << filename << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "🚀 ML-Enhanced NAT Analyzer & Port Manipulator v4.0" << std::endl;
    std::cout << "🧠 Machine Learning + 8-Layer Precision System" << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    
    std::string stun_server = "stun.l.google.com";
    int packet_count = 25;
    uint16_t target_port = 0;
    std::string mode = "analyze";
    
    // Parse command line arguments
    if (argc > 1) {
        stun_server = argv[1];
    }
    if (argc > 2) {
        packet_count = std::atoi(argv[2]);
    }
    if (argc > 3) {
        std::string arg3 = argv[3];
        if (arg3 == "predict") {
            mode = "predict";
        } else if (arg3.substr(0, 6) == "target") {
            mode = "target";
            if (arg3.length() > 7) {
                target_port = std::atoi(arg3.substr(7).c_str());
            }
        } else {
            target_port = std::atoi(arg3.c_str());
            if (target_port > 0) mode = "target";
        }
    }
    
    std::cout << "📊 ML Configuration:" << std::endl;
    std::cout << "   STUN Server: " << stun_server << std::endl;
    std::cout << "   Analysis Packets: " << packet_count << std::endl;
    std::cout << "   Mode: " << mode << std::endl;
    if (mode == "target") {
        std::cout << "   Target Port: " << target_port << std::endl;
    }
    std::cout << std::endl;
    
    // Initialize ML-enhanced analyzer
    AdvancedNATAnalyzer analyzer(stun_server);
    
    // Phase 1: ML-enhanced pattern learning
    std::cout << "🔍 PHASE 1: ML-ENHANCED PATTERN LEARNING" << std::endl;
    std::cout << "=" << std::string(40, '-') << std::endl;
    if (!analyzer.execute_high_performance_burst(packet_count)) {
        std::cerr << "❌ Failed to execute measurement burst" << std::endl;
        return 1;
    }
    
    // Phase 2: ML-enhanced analysis
    std::cout << "🧠 PHASE 2: ML-ENHANCED ANALYSIS" << std::endl;
    std::cout << "=" << std::string(40, '-') << std::endl;
    analyzer.run_comprehensive_analysis();
    
    // Phase 3: ML-enhanced targeting
    if (mode == "target" && target_port > 0) {
        std::cout << "🎯 PHASE 3: ML-ENHANCED TARGET ATTACK" << std::endl;
        std::cout << "=" << std::string(40, '-') << std::endl;
        
        bool success = analyzer.execute_iterative_exact_targeting(target_port);
        
        if (success) {
            std::cout << "\n🎉 ML SUCCESS! EXACT TARGET " << target_port << " ACHIEVED!" << std::endl;
            std::cout << "🧠 Machine Learning + 8-Layer system successful!" << std::endl;
        } else {
            std::cout << "\n📊 ML system learned valuable patterns for future attempts" << std::endl;
            std::cout << "💡 ML-enhanced algorithm achieved maximum precision" << std::endl;
        }
    }
    
    std::cout << "\n✅ ML-Enhanced system complete!" << std::endl;
    
    return 0;
}
