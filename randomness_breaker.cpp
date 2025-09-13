#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <map>
#include <set>
#include <cmath>
#include <complex>
#include <fstream>
#include <random> // Yeni: Rastgele sayı üretimi için
#include <tuple> // Yeni: Markov chain için tuple

// STUN sabitleri ve yapıları (mevcut koddan alınmıştır)
struct STUNHeader {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
};

struct PacketMeasurement {
    uint16_t assigned_port;
    uint64_t timestamp_us;
    int sequence_number;
    uint16_t source_port;
    std::string target_ip;
    bool success;
};

struct PortPrediction {
    uint16_t predicted_port;
    double confidence;
    std::string method;
    int steps_ahead;
};

// Global veya sınıf üyesi olarak tanımlanacaklar
std::string target_stun_server;
uint16_t stun_port;
int socket_fd;
std::vector<PacketMeasurement> measurements;

// Rastgele sayı üreteci için global veya sınıf üyesi
std::mt19937 rng; // Mersenne Twister motoru
std::uniform_int_distribution<uint8_t> byte_dist(0, 255); // 0-255 arası byte dağıtımı

// Fonksiyon prototipleri (mevcut koddan alınmıştır)
void create_stun_binding_request(uint8_t* buffer, uint8_t* transaction_id);
void resolve_hostname_to_ip();
uint64_t get_timestamp_us();
uint16_t parse_mapped_address(uint8_t* buffer, size_t length);
bool collect_stun_responses_multi_socket(const std::vector<int>& sockets, int expected_responses, uint64_t start_time);

void basic_statistics_analysis(const std::vector<uint16_t>& ports);
void entropy_analysis(const std::vector<uint16_t>& ports);
void delta_port_analysis(const std::vector<uint16_t>& ports);
void autocorrelation_analysis(const std::vector<uint16_t>& ports);
void periodicity_detection(const std::vector<uint16_t>& ports);
int berlekamp_massey(const std::vector<int>& sequence);
void berlekamp_massey_analysis(const std::vector<uint16_t>& ports);
void lfsr_prediction(const std::vector<uint16_t>& ports);
void markov_chain_analysis(const std::vector<uint16_t>& ports);
void bit_plane_entropy_analysis(const std::vector<uint16_t>& ports);
void chi_square_uniformity_test(const std::vector<uint16_t>& ports);
void spectral_analysis(const std::vector<uint16_t>& ports);

std::vector<PortPrediction> predict_next_ports(int count);
std::vector<PortPrediction> predict_using_markov_chain(int count);
std::vector<PortPrediction> predict_using_delta_patterns(int count);
std::vector<PortPrediction> predict_using_lfsr_state(int count);

bool execute_targeted_port_manipulation(uint16_t target_port, int max_attempts);
bool execute_precise_sequence_to_target(uint16_t target_port, int steps_needed);
bool execute_iterative_exact_targeting(uint16_t target_port);
bool execute_micro_adjustment(uint16_t target_port, uint16_t current_port);
uint16_t execute_distance_specific_attack(uint16_t current_port, uint16_t target_port, int attempts);
bool execute_precision_brute_force(uint16_t target_port, uint16_t current_port);
uint16_t execute_single_targeted_request(uint16_t source_port);
bool execute_pattern_guided_search(uint16_t target_port, int max_attempts);
void save_results_to_file();


// Constructor ve Destructor (mevcut koddan alınmıştır)
void initialize_analyzer(const std::string& server, uint16_t port) {
    target_stun_server = server;
    stun_port = port;
    socket_fd = -1; // Initialize socket_fd
    // RNG'yi başlat (isteğe bağlı olarak deterministik bir seed ile)
    // std::random_device rd; // Gerçek rastgelelik için
    // rng.seed(rd());       // Gerçek rastgelelik için
    rng.seed(0); // Testler için deterministik bir seed
    std::cout << "🚀 Advanced C++ NAT Analyzer - High Performance + Pattern Detection" << std::endl;
    std::cout << "Target STUN Server: " << target_stun_server << ":" << stun_port << std::endl;
}

void cleanup_analyzer() {
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
    header->type = htons(0x0001);
    header->length = 0;
    header->magic_cookie = htonl(0x2112A442);
    memcpy(header->transaction_id, transaction_id, 12);
}

void resolve_hostname_to_ip() {
    if (target_stun_server == "stun.l.google.com") {
        target_stun_server = "74.125.250.129"; // Örnek için sabit IP
    }
    std::cout << "📍 Resolved to: " << target_stun_server << std::endl;
}

bool execute_high_performance_burst(int packet_count, uint16_t start_port = 0) {
    std::cout << "🔥 Starting high-performance burst: " << packet_count << " packets" << std::endl;
    std::cout << "🎯 Strategy: Each packet from different source port for unique NAT sessions" << std::endl;
    
    resolve_hostname_to_ip();
    
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(stun_port);
    if (inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Invalid IP address for STUN server." << std::endl;
        return false;
    }
    
    measurements.clear();
    measurements.reserve(packet_count);
    
    auto start_time = get_timestamp_us();
    
    std::vector<int> sockets(packet_count);
    std::vector<struct sockaddr_in> source_addrs(packet_count);
    
    std::vector<uint8_t> buffers(packet_count * 20);
    std::vector<uint8_t> transaction_ids_storage(packet_count * 12); // Transaction ID'leri saklamak için
    
    for (int i = 0; i < packet_count; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockets[i] < 0) {
            perror("Socket creation failed");
            // Mevcut soketleri kapat ve hata döndür
            for(int j = 0; j < i; ++j) close(sockets[j]);
            return false;
        }
        
        memset(&source_addrs[i], 0, sizeof(source_addrs[i]));
        source_addrs[i].sin_family = AF_INET;
        source_addrs[i].sin_addr.s_addr = INADDR_ANY;
        source_addrs[i].sin_port = htons(start_port + 10000 + i);
        
        if (bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i])) < 0) {
            // Bind başarısız olursa, çekirdeğin port seçmesine izin ver
            source_addrs[i].sin_port = 0;
            if (bind(sockets[i], (struct sockaddr*)&source_addrs[i], sizeof(source_addrs[i])) < 0) {
                perror("Bind failed for source port, even with 0. Skipping this socket.");
                close(sockets[i]);
                sockets[i] = -1; // İşlemeyen soketi işaretle
                continue;
            }
        }
        
        uint8_t* buffer = &buffers[i * 20];
        uint8_t* trans_id = &transaction_ids_storage[i * 12];
        
        // Yeni: std::mt19937 ve std::uniform_int_distribution kullanarak transaction ID üretimi
        for (int j = 0; j < 12; ++j) {
            trans_id[j] = byte_dist(rng);
        }
        
        create_stun_binding_request(buffer, trans_id);
    }
    
    std::cout << "📦 Prepared " << packet_count << " STUN messages with unique source ports" << std::endl;
    std::cout << "🚀 Executing individual socket sends for NAT diversity..." << std::endl;
    
    auto burst_start = get_timestamp_us();
    int sent = 0;
    
    for (int i = 0; i < packet_count; ++i) {
        if (sockets[i] == -1) continue; // Bağlanamayan soketleri atla
        ssize_t result = sendto(sockets[i], buffers.data() + i * 20, 20, 0,
                               (struct sockaddr*)&target_addr, sizeof(target_addr));
        if (result > 0) {
            sent++;
        } else {
            std::cerr << "Warning: sendto failed for socket " << i << ": " << strerror(errno) << std::endl;
        }
    }
    
    auto burst_end = get_timestamp_us();
    
    std::cout << "✅ Burst complete: " << sent << "/" << packet_count << " packets sent" << std::endl;
    
    double burst_duration_s = (burst_end - burst_start) / 1e6;
    double packet_rate = (sent > 0 && burst_duration_s > 0) ? (sent / burst_duration_s) : 0.0;
    
    std::cout << "⚡ Burst Performance:" << std::endl;
    std::cout << "   Duration: " << std::fixed << std::setprecision(3) 
              << burst_duration_s << "s" << std::endl;
    std::cout << "   Rate: " << std::fixed << std::setprecision(0) 
              << packet_rate << " packets/second" << std::endl;
    
    // Şimdi tüm soketlerden yanıtları topla
    // Yalnızca başarılı bir şekilde oluşturulan ve gönderilen soketleri ilet
    std::vector<int> active_sockets;
    for(int sock : sockets) {
        if(sock != -1) active_sockets.push_back(sock);
    }
    
    bool result = collect_stun_responses_multi_socket(active_sockets, sent, start_time);
    
    // Tüm soketleri kapat
    for (int sock : sockets) {
        if (sock != -1) close(sock);
    }
    
    return result;
}

bool collect_stun_responses_multi_socket(const std::vector<int>& sockets, int expected_responses, uint64_t start_time) {
    std::cout << "📡 Collecting STUN responses from multiple sockets..." << std::endl;
    
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    
    for (int sock : sockets) {
        if (sock != -1) {
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        }
    }
    
    uint8_t response_buffer[1500];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    int responses_received = 0;
    auto collection_start = get_timestamp_us();
    
    // Tüm soketleri dinlemek için select kullan
    fd_set read_fds;
    int max_fd = 0;
    for (int sock : sockets) {
        if (sock != -1) {
            if (sock > max_fd) max_fd = sock;
        }
    }

    // Koleksiyon süresini kısıtla
    auto collection_end_time = collection_start + (10 * 1e6); // 10 saniye toplam koleksiyon süresi

    while (responses_received < expected_responses && get_timestamp_us() < collection_end_time) {
        FD_ZERO(&read_fds);
        bool has_active_socket = false;
        for (int sock : sockets) {
            if (sock != -1) {
                FD_SET(sock, &read_fds);
                has_active_socket = true;
            }
        }
        
        if (!has_active_socket) {
            std::cout << "No active sockets to listen on." << std::endl;
            break;
        }

        struct timeval select_timeout = {1, 0}; // Her select çağrısı için 1 saniye timeout
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &select_timeout);

        if (activity < 0) {
            perror("select error");
            break;
        }
        if (activity == 0) { // Timeout
            std::cout << "⏰ Select timeout, still waiting for responses..." << std::endl;
            continue;
        }

        for (size_t i = 0; i < sockets.size() && responses_received < expected_responses; ++i) {
            int sock = sockets[i];
            if (sock != -1 && FD_ISSET(sock, &read_fds)) {
                ssize_t bytes_received = recvfrom(sock, response_buffer, sizeof(response_buffer),
                                                0, (struct sockaddr*)&from_addr, &from_len);
                
                if (bytes_received >= 20) {
                    STUNHeader* header = reinterpret_cast<STUNHeader*>(response_buffer);
                    
                    if (ntohs(header->type) == 0x0101) {
                        uint16_t assigned_port = parse_mapped_address(response_buffer, bytes_received);
                        
                        if (assigned_port > 0) {
                            PacketMeasurement measurement;
                            measurement.assigned_port = assigned_port;
                            measurement.timestamp_us = get_timestamp_us();
                            measurement.sequence_number = responses_received;
                            measurement.source_port = 10000 + i;
                            measurement.target_ip = target_stun_server;
                            measurement.success = true;
                            
                            measurements.push_back(measurement);
                            responses_received++;
                            
                            if (responses_received % 10 == 0 || responses_received <= 20) {
                                std::cout << "📊 Response " << responses_received 
                                          << " (src:" << measurement.source_port << "): Port " 
                                          << assigned_port << std::endl;
                            }
                        }
                    }
                } else if (bytes_received < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom failed on an active socket");
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
    std::cout << "   Success Rate: " << (expected_responses > 0 ? (100.0 * responses_received / expected_responses) : 0.0) << "%" << std::endl;
    
    return responses_received > 0;
}

uint16_t parse_mapped_address(uint8_t* buffer, size_t length) {
    uint8_t* ptr = buffer + 20;
    uint8_t* end = buffer + length;
    
    while (ptr + 4 <= end) {
        uint16_t attr_type = ntohs(*reinterpret_cast<uint16_t*>(ptr));
        uint16_t attr_length = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
        ptr += 4;
        
        if (ptr + attr_length > end) break;
        
        if (attr_type == 0x0001 || attr_type == 0x0020) {
            if (attr_length >= 8) {
                uint16_t port = ntohs(*reinterpret_cast<uint16_t*>(ptr + 2));
                
                if (attr_type == 0x0020) {
                    port ^= 0x2112;
                }
                
                return port;
            }
        }
        
        ptr += attr_length;
        while ((ptr - buffer) % 4 != 0 && ptr < end) ptr++;
    }
    
    return 0;
}

// --- PRNG Seed Brute-Force ve Model Deneme ---

// LCG parametreleri (rand() için tipik değerler)
struct LCGParams {
    uint32_t a, c, m, port_min, port_max;
    std::string name;
};
const std::vector<LCGParams> lcg_models = {
    {1103515245, 12345, 1u << 31, 1024, 65535, "glibc rand()"},
    {1664525, 1013904223, 1u << 32, 1024, 65535, "MSVC LCG"},
    {214013, 2531011, 1u << 31, 1024, 65535, "MS rand()"}
};

// LCG brute-force
bool try_lcg_seed(uint32_t seed, const std::vector<uint16_t>& observed_ports, const LCGParams& params, int max_check = 10) {
    uint32_t state = seed;
    for (size_t i = 0; i < std::min<size_t>(observed_ports.size(), max_check); ++i) {
        state = (params.a * state + params.c) % params.m;
        uint16_t predicted_port = params.port_min + (state % (params.port_max - params.port_min + 1));
        if (predicted_port != observed_ports[i]) return false;
    }
    return true;
}

// Mersenne Twister brute-force (seed aralığı küçükse)
bool try_mt19937_seed(uint32_t seed, const std::vector<uint16_t>& observed_ports, int max_check = 10) {
    std::mt19937 mt(seed);
    for (size_t i = 0; i < std::min<size_t>(observed_ports.size(), max_check); ++i) {
        uint16_t predicted_port = 1024 + (mt() % (65536 - 1024));
        if (predicted_port != observed_ports[i]) return false;
    }
    return true;
}

// Ana brute-force fonksiyonu
void brute_force_prng_seed(const std::vector<uint16_t>& ports, uint64_t first_timestamp_us) {
    if (ports.size() < 5) {
        std::cout << "❌ Not enough data for brute-force seed search." << std::endl;
        return;
    }
    std::cout << "\n🚦 PRNG Seed Brute-Force Search" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    // Zaman aralığını belirle (ör: ilk portun timestamp'ı +- 10 saniye)
    uint32_t t0 = static_cast<uint32_t>(first_timestamp_us / 1000000);
    uint32_t t_start = t0 - 10, t_end = t0 + 10;

    // LCG brute-force
    for (const auto& params : lcg_models) {
        std::cout << "🔍 Trying LCG model: " << params.name << std::endl;
        for (uint32_t seed = t_start; seed <= t_end; ++seed) {
            if (try_lcg_seed(seed, ports, params, 10)) {
                std::cout << "   ✅ Seed found: " << seed << " (epoch time)" << std::endl;
                std::cout << "   Model: " << params.name << std::endl;
                return;
            }
        }
    }

    // Mersenne Twister brute-force (dar aralıkta)
    std::cout << "🔍 Trying Mersenne Twister (std::mt19937)..." << std::endl;
    for (uint32_t seed = t_start; seed <= t_end; ++seed) {
        if (try_mt19937_seed(seed, ports, 10)) {
            std::cout << "   ✅ Seed found: " << seed << " (epoch time)" << std::endl;
            std::cout << "   Model: std::mt19937" << std::endl;
            return;
        }
    }

    std::cout << "❌ No matching seed found in time window." << std::endl;
}

// Analiz fonksiyonuna ekle
void run_comprehensive_analysis() {
    if (measurements.empty()) {
        std::cout << "❌ No measurement data available for analysis" << std::endl;
        return;
    }
    std::cout << "\n🔬 COMPREHENSIVE PATTERN ANALYSIS" << std::endl;
    std::cout << "=" << std::string(50, '=') << std::endl;
    std::cout << "📊 Dataset: " << measurements.size() << " measurements" << std::endl;

    std::vector<uint16_t> ports;
    for (const auto& m : measurements) {
        ports.push_back(m.assigned_port);
    }

    basic_statistics_analysis(ports);
    entropy_analysis(ports);
    delta_port_analysis(ports);
    autocorrelation_analysis(ports);
    periodicity_detection(ports);
    berlekamp_massey_analysis(ports);
    lfsr_prediction(ports);
    markov_chain_analysis(ports);
    bit_plane_entropy_analysis(ports);
    chi_square_uniformity_test(ports);
    spectral_analysis(ports);

    // PRNG brute-force ekle
    brute_force_prng_seed(ports, measurements[0].timestamp_us);

    save_results_to_file();
}

void basic_statistics_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n📈 BASIC STATISTICS:" << std::endl;
    
    if (ports.empty()) {
        std::cout << "   No data for basic statistics." << std::endl;
        return;
    }

    uint16_t min_port = *std::min_element(ports.begin(), ports.end());
    uint16_t max_port = *std::max_element(ports.begin(), ports.end());
    double mean_port = static_cast<double>(std::accumulate(ports.begin(), ports.end(), 0.0)) / ports.size();
    
    double variance = 0.0;
    for (uint16_t port : ports) {
        variance += (port - mean_port) * (port - mean_port);
    }
    variance /= ports.size();
    double std_dev = std::sqrt(variance);
    
    std::cout << "   Port Range: " << min_port << " - " << max_port << std::endl;
    std::cout << "   Port Span: " << (max_port - min_port) << std::endl;
    std::cout << "   Mean Port: " << std::fixed << std::setprecision(1) << mean_port << std::endl;
    std::cout << "   Std Dev: " << std::fixed << std::setprecision(1) << std_dev << std::endl;
    
    std::set<uint16_t> unique_ports(ports.begin(), ports.end());
    std::cout << "   Unique Ports: " << unique_ports.size() << "/" << ports.size();
    if (unique_ports.size() < ports.size()) {
        std::cout << " (REUSE DETECTED!)";
    }
    std::cout << std::endl;
}

void entropy_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n🎯 ENTROPY ANALYSIS:" << std::endl;

    if (ports.empty()) {
        std::cout << "   No data for entropy analysis." << std::endl;
        return;
    }
    
    std::map<uint16_t, int> freq;
    for (uint16_t port : ports) {
        freq[port]++;
    }
    
    double shannon_entropy = 0.0;
    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / ports.size();
        shannon_entropy -= p * std::log2(p);
    }
    
    double max_entropy = std::log2(ports.size());
    double entropy_ratio = (max_entropy > 0) ? (shannon_entropy / max_entropy) : 0.0;
    
    std::cout << "   Shannon Entropy: " << std::fixed << std::setprecision(3) 
              << shannon_entropy << " bits" << std::endl;
    std::cout << "   Max Possible: " << std::fixed << std::setprecision(3) 
              << max_entropy << " bits" << std::endl;
    std::cout << "   Entropy Ratio: " << std::fixed << std::setprecision(3) 
              << entropy_ratio << " (" << (entropy_ratio * 100) << "%)" << std::endl;
}

void delta_port_analysis(const std::vector<uint16_t>& ports) {
    if (ports.size() < 2) {
        std::cout << "\n📊 PORT DELTA ANALYSIS: Not enough data." << std::endl;
        return;
    }
    
    std::cout << "\n📊 PORT DELTA ANALYSIS:" << std::endl;
    
    std::map<int32_t, int> delta_freq;
    std::vector<int32_t> deltas;
    
    for (size_t i = 1; i < ports.size(); ++i) {
        int32_t delta = static_cast<int32_t>(ports[i]) - static_cast<int32_t>(ports[i-1]);
        deltas.push_back(delta);
        delta_freq[delta]++;
    }
    
    std::vector<std::pair<int32_t, int>> sorted_deltas(delta_freq.begin(), delta_freq.end());
    std::sort(sorted_deltas.begin(), sorted_deltas.end(), 
             [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::cout << "   Most Common Deltas:" << std::endl;
    for (size_t i = 0; i < std::min(size_t(5), sorted_deltas.size()); ++i) {
        std::cout << "     Δ" << sorted_deltas[i].first 
                  << ": " << sorted_deltas[i].second << " times" << std::endl;
    }
    
    double mean_delta = (deltas.empty()) ? 0.0 : static_cast<double>(std::accumulate(deltas.begin(), deltas.end(), 0.0)) / deltas.size();
    std::cout << "   Mean Delta: " << std::fixed << std::setprecision(1) << mean_delta << std::endl;
}

void autocorrelation_analysis(const std::vector<uint16_t>& ports) {
    if (ports.size() < 10) {
        std::cout << "\n🔄 AUTOCORRELATION ANALYSIS: Not enough data (min 10 points)." << std::endl;
        return;
    }
    
    std::cout << "\n🔄 AUTOCORRELATION ANALYSIS:" << std::endl;
    
    double mean = static_cast<double>(std::accumulate(ports.begin(), ports.end(), 0.0)) / ports.size();
    
    std::cout << "   Lag | Correlation" << std::endl;
    std::cout << "   ----|------------" << std::endl;
    
    for (int lag = 1; lag <= std::min(10, static_cast<int>(ports.size())/2); ++lag) {
        double numerator = 0.0;
        double denominator = 0.0;
        
        for (size_t i = 0; i + lag < ports.size(); ++i) {
            numerator += (ports[i] - mean) * (ports[i + lag] - mean);
        }
        
        for (size_t i = 0; i < ports.size(); ++i) {
            denominator += (ports[i] - mean) * (ports[i] - mean);
        }
        
        double correlation = (denominator != 0) ? numerator / denominator : 0.0;
        
        std::cout << "   " << std::setw(3) << lag << " | " 
                  << std::fixed << std::setprecision(4) << correlation;
        
        if (std::abs(correlation) > 0.1) {
            std::cout << " *** SIGNIFICANT ***";
        }
        std::cout << std::endl;
    }
}

void periodicity_detection(const std::vector<uint16_t>& ports) {
    std::cout << "\n🔄 PERIODICITY DETECTION:" << std::endl;
    
    if (ports.size() < 4) {
        std::cout << "   Not enough data for periodicity detection (min 4 points)." << std::endl;
        return;
    }

    std::map<size_t, int> period_candidates;
    
    // Period en az 2 olmalı ve veri setinin 1/3'ünden büyük olmamalı
    for (size_t period = 2; period <= ports.size()/3; ++period) {
        bool is_periodic = true;
        // İlk 'period' elemanı kontrol et
        for (size_t i = 0; i + period < ports.size(); ++i) {
            if (ports[i] != ports[i + period]) {
                is_periodic = false;
                break;
            }
        }
        
        if (is_periodic) {
            period_candidates[period]++;
        }
    }
    
    if (period_candidates.empty()) {
        std::cout << "   No clear periodicity detected" << std::endl;
    } else {
        std::cout << "   Potential Periods:" << std::endl;
        for (const auto& pair : period_candidates) {
            std::cout << "     Period " << pair.first << std::endl; // Confidence yerine sadece periyodu göster
        }
    }
}

int berlekamp_massey(const std::vector<int>& sequence) {
    int n = sequence.size();
    if (n == 0) return 0;

    std::vector<int> c(n), b(n);
    c[0] = 1; b[0] = 1; // Polynomials for current and previous LFSR
    int L = 0; // Length of the shortest LFSR
    int m = -1; // Position of the last change in L

    for (int i = 0; i < n; ++i) {
        int delta = sequence[i]; // Discrepancy
        for (int j = 1; j <= L; ++j) {
            delta ^= (c[j] & sequence[i - j]); // XOR is equivalent to addition in GF(2)
        }

        if (delta == 0) { // Discrepancy is zero, current LFSR generates sequence[i]
            continue;
        }

        // Discrepancy is non-zero, need to update LFSR
        std::vector<int> t = c; // Save current C(x)
        for (int j = 0; j < n - (i - m); ++j) { // C(x) = C(x) ^ (B(x) * x^(i-m))
            c[j + (i - m)] ^= b[j];
        }

        if (2 * L <= i) { // Update L and B(x)
            L = i + 1 - L;
            m = i;
            b = t; // B(x) becomes previous C(x)
        }
    }
    return L;
}


void berlekamp_massey_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n🧮 BERLEKAMP-MASSEY LINEAR COMPLEXITY:" << std::endl;
    
    if (ports.empty()) {
        std::cout << "   No data for Berlekamp-Massey analysis." << std::endl;
        return;
    }

    std::vector<int> bit_sequence;
    for (uint16_t port : ports) {
        for (int i = 15; i >= 0; --i) { // 16 bitlik portları bit dizisine çevir
            bit_sequence.push_back((port >> i) & 1);
        }
    }
    
    if (bit_sequence.empty()) {
        std::cout << "   Bit sequence is empty." << std::endl;
        return;
    }

    int linear_complexity = berlekamp_massey(bit_sequence);
    
    std::cout << "   Bit Sequence Length: " << bit_sequence.size() << std::endl;
    std::cout << "   Linear Complexity: " << linear_complexity << std::endl;
    double complexity_ratio = (bit_sequence.size() > 0) ? static_cast<double>(linear_complexity) / bit_sequence.size() : 0.0;
    std::cout << "   Complexity Ratio: " << std::fixed << std::setprecision(3) 
              << complexity_ratio << std::endl;
    
    if (linear_complexity < bit_sequence.size() / 2) { // Genellikle yarıdan az olması zayıf rastgelelik göstergesidir
        std::cout << "   ⚠️  LOW COMPLEXITY - PREDICTABLE SEQUENCE DETECTED!" << std::endl;
    } else {
        std::cout << "   ✅ High complexity - appears random" << std::endl;
    }
}

void lfsr_prediction(const std::vector<uint16_t>& ports) {
    if (ports.size() < 10) {
        std::cout << "\n🔮 LFSR PREDICTION: Not enough data (min 10 points)." << std::endl;
        return;
    }
}

// main fonksiyonu, programın giriş noktası
int main(int argc, char* argv[]) {
    // Varsayılan STUN sunucusu ve portu
    std::string stun_server = "stun.l.google.com";
    uint16_t stun_port_num = 19302;
    int packet_count = 50; // Analiz için toplanacak port sayısı

    // Komut satırı argümanlarını işle
    if (argc > 1) stun_server = argv[1];
    if (argc > 2) stun_port_num = static_cast<uint16_t>(std::stoi(argv[2]));
    if (argc > 3) packet_count = std::stoi(argv[3]);

    // Analiz aracını başlat
    initialize_analyzer(stun_server, stun_port_num);

    // Port atamalarını toplamak için STUN sunucusuna istek gönder
    if (!execute_high_performance_burst(packet_count)) {
        std::cerr << "Error: Failed to collect port measurements." << std::endl;
        cleanup_analyzer();
        return 1;
    }

    // Toplanan verilerle kapsamlı analizi ve seed brute-force'u çalıştır
    run_comprehensive_analysis();

    // Kaynakları temizle
    cleanup_analyzer();
    return 0;
}
