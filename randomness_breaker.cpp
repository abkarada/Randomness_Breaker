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
#include <cmath> // M_PI için gerekli
#include <unistd.h> // usleep için

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

// NAT Traversal ve P2P Hole Punching fonksiyonları
struct PeerInfo {
    std::string public_ip;
    uint16_t public_port;
    std::string private_ip;
    uint16_t private_port;
    std::string nat_type;
    uint64_t last_seen;
};

// Birthday-Paradox ve Entropi Haritası için yapılar
struct STUNTarget {
    std::string ip;
    uint16_t port;
    std::string hostname;
    double rtt_avg;
    bool active;
};

struct PortBin {
    uint16_t start_port;
    uint16_t end_port;
    int frequency;
    double entropy;
    double time_correlation;
    bool is_hot;
};

struct PRNGModel {
    std::string type; // "LCG", "MT19937", "XORSHIFT", "ENTROPY_ONLY"
    uint32_t seed;
    double confidence;
    std::vector<uint32_t> parameters; // a, c, m için LCG vs.
    uint16_t predicted_range_start;
    uint16_t predicted_range_end;
    int prediction_accuracy; // %
};

struct EntropyHeatmap {
    std::vector<PortBin> bins;
    uint16_t effective_range_start;
    uint16_t effective_range_end;
    int n_effective; // Daraltılmış port uzayı boyutu
    double concentration_ratio; // Sıcak bölgelerin oranı
};

struct BirthdayParadoxPlan {
    int m_optimal; // Gerekli atış sayısı
    int n_space; // Port uzayı boyutu
    double success_probability; // Hedef başarı olasılığı
    std::vector<int> stealth_batches; // Aşamalı burst boyutları
    bool use_phase_lock;
    int phase_period_ms;
};

struct GlobalClockSync {
    uint64_t ntp_offset_us;
    uint64_t ptp_offset_us;
    bool is_synchronized;
    double accuracy_us;
};

// Yeni fonksiyon prototipleri
std::vector<STUNTarget> select_multi_stun_targets(int count = 5);
EntropyHeatmap measure_phase_multi_stun(const std::vector<STUNTarget>& targets, int burst_size = 512);
PRNGModel attempt_prng_seed_extraction(const std::vector<PacketMeasurement>& measurements);
BirthdayParadoxPlan calculate_birthday_paradox_plan(int n_space, double target_prob = 0.99);
std::vector<uint16_t> generate_weighted_port_candidates(const EntropyHeatmap& heatmap, int count);
bool execute_simultaneous_punch_with_birthday_paradox(const BirthdayParadoxPlan& plan, 
                                                     const EntropyHeatmap& heatmap,
                                                     const PeerInfo& peer);
bool execute_stealth_burst_attack(const std::vector<uint16_t>& port_candidates, 
                                 const std::string& target_ip, 
                                 const BirthdayParadoxPlan& plan);
GlobalClockSync initialize_global_clock_sync();
void align_to_phase_period(int phase_period_ms);
bool detect_collision_promiscuous();
void execute_master_nat_traversal_strategy();
bool execute_targeted_port_attack(uint16_t target_port);
uint16_t execute_single_request_to_destination(uint16_t source_port, const std::string& dest_ip, uint16_t dest_port);

struct HolePunchResult {
    bool success;
    uint16_t local_port;
    uint16_t remote_port;
    std::string method_used;
    double time_taken_ms;
};

bool execute_nat_type_detection();
bool execute_symmetric_nat_prediction_attack(const std::string& target_ip, uint16_t target_port);
HolePunchResult execute_hole_punching(const PeerInfo& peer);
bool execute_port_prediction_hole_punch(const PeerInfo& peer, const std::vector<uint16_t>& predicted_ports);
bool send_hole_punch_packets(const std::string& target_ip, const std::vector<uint16_t>& target_ports, uint16_t local_port);
std::vector<uint16_t> generate_port_candidates(uint16_t last_known_port, int count);
bool establish_p2p_connection(const PeerInfo& peer);
void run_p2p_server(uint16_t listen_port);
bool test_p2p_connectivity(const std::string& peer_ip, uint16_t peer_port);

bool execute_targeted_port_manipulation(uint16_t target_port, int max_attempts);
bool execute_precise_sequence_to_target(uint16_t target_port, int steps_needed);
bool execute_iterative_exact_targeting(uint16_t target_port);
bool execute_micro_adjustment(uint16_t target_port, uint16_t current_port);
uint16_t execute_distance_specific_attack(uint16_t current_port, uint16_t target_port, int attempts);
bool execute_precision_brute_force(uint16_t target_port, uint16_t current_port);
uint16_t execute_single_targeted_request(uint16_t source_port);
bool execute_pattern_guided_search(uint16_t target_port, int max_attempts);
void save_results_to_file();
void timestamp_port_correlation_analysis(const std::vector<PacketMeasurement>& measurements);
void source_port_assigned_port_analysis(const std::vector<PacketMeasurement>& measurements);


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
    uint32_t a, c;
    uint64_t m;
    uint16_t port_min, port_max;
    std::string name;
};
const std::vector<LCGParams> lcg_models = {
    {1103515245, 12345, 1u << 31, 1024, 65535, "glibc rand()"},
    {1664525, 1013904223, 1ULL << 32, 1024, 65535, "MSVC LCG"},
    {214013, 2531011, 1u << 31, 1024, 65535, "MS rand()"}
};

// LCG brute-force
bool try_lcg_seed(uint32_t seed, const std::vector<uint16_t>& observed_ports, const LCGParams& params, int max_check = 10) {
    uint64_t state = seed;
    for (size_t i = 0; i < std::min<size_t>(observed_ports.size(), max_check); ++i) {
        state = (static_cast<uint64_t>(params.a) * state + params.c) % params.m;
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

    // Yeni analizler: Timestamp ve Source Port ilişkileri
    timestamp_port_correlation_analysis(measurements);
    source_port_assigned_port_analysis(measurements);

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
             [](const std::pair<int32_t, int>& a, const std::pair<int32_t, int>& b) { return a.second > b.second; });
    
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

void timestamp_port_correlation_analysis(const std::vector<PacketMeasurement>& measurements) {
    std::cout << "\n⏰ TIMESTAMP vs ASSIGNED PORT CORRELATION:" << std::endl;
    
    if (measurements.size() < 2) {
        std::cout << "   Not enough data." << std::endl;
        return;
    }
    
    // Timestamp'leri ve portları çıkar
    std::vector<double> timestamps, ports;
    for (const auto& m : measurements) {
        timestamps.push_back(static_cast<double>(m.timestamp_us));
        ports.push_back(static_cast<double>(m.assigned_port));
    }
    
    // Ortalamaları hesapla
    double mean_ts = std::accumulate(timestamps.begin(), timestamps.end(), 0.0) / timestamps.size();
    double mean_port = std::accumulate(ports.begin(), ports.end(), 0.0) / ports.size();
    
    // Kovaryans ve varyans hesapla
    double cov = 0.0, var_ts = 0.0, var_port = 0.0;
    for (size_t i = 0; i < timestamps.size(); ++i) {
        cov += (timestamps[i] - mean_ts) * (ports[i] - mean_port);
        var_ts += (timestamps[i] - mean_ts) * (timestamps[i] - mean_ts);
        var_port += (ports[i] - mean_port) * (ports[i] - mean_port);
    }
    
    double correlation = (var_ts > 0 && var_port > 0) ? cov / std::sqrt(var_ts * var_port) : 0.0;
    
    std::cout << "   Correlation: " << std::fixed << std::setprecision(4) << correlation << std::endl;
    
    if (std::abs(correlation) > 0.5) {
        std::cout << "   ⚠️  STRONG CORRELATION DETECTED! Timestamp may influence port assignment." << std::endl;
    } else if (std::abs(correlation) > 0.3) {
        std::cout << "   📊 Moderate correlation." << std::endl;
    } else {
        std::cout << "   ✅ Weak or no correlation." << std::endl;
    }
    
    // Linear regression: port = a * timestamp + b
    double a = cov / var_ts;
    double b = mean_port - a * mean_ts;
    
    std::cout << "   Linear Fit: port ≈ " << std::fixed << std::setprecision(2) << a << " * timestamp + " << b << std::endl;
    
    // Tahmin örneği
    if (!measurements.empty()) {
        uint64_t next_ts = measurements.back().timestamp_us + 1000000; // 1 saniye sonra
        uint16_t predicted = static_cast<uint16_t>(std::round(a * next_ts + b));
        std::cout << "   Next predicted port (1s later): " << predicted << std::endl;
    }
}

void source_port_assigned_port_analysis(const std::vector<PacketMeasurement>& measurements) {
    std::cout << "\n🔗 SOURCE PORT vs ASSIGNED PORT ANALYSIS:" << std::endl;
    
    if (measurements.size() < 2) {
        std::cout << "   Not enough data." << std::endl;
        return;
    }
    
    // Source portları ve assigned portları çıkar
    std::vector<double> src_ports, assigned_ports;
    for (const auto& m : measurements) {
        src_ports.push_back(static_cast<double>(m.source_port));
        assigned_ports.push_back(static_cast<double>(m.assigned_port));
    }
    
    // Ortalamaları hesapla
    double mean_src = std::accumulate(src_ports.begin(), src_ports.end(), 0.0) / src_ports.size();
    double mean_assigned = std::accumulate(assigned_ports.begin(), assigned_ports.end(), 0.0) / assigned_ports.size();
    
    // Kovaryans ve varyans hesapla
    double cov = 0.0, var_src = 0.0, var_assigned = 0.0;
    for (size_t i = 0; i < src_ports.size(); ++i) {
        cov += (src_ports[i] - mean_src) * (assigned_ports[i] - mean_assigned);
        var_src += (src_ports[i] - mean_src) * (src_ports[i] - mean_src);
        var_assigned += (assigned_ports[i] - mean_assigned) * (assigned_ports[i] - mean_assigned);
    }
    
    double correlation = (var_src > 0 && var_assigned > 0) ? cov / std::sqrt(var_src * var_assigned) : 0.0;
    
    std::cout << "   Correlation: " << std::fixed << std::setprecision(4) << correlation << std::endl;
    
    if (std::abs(correlation) > 0.5) {
        std::cout << "   ⚠️  STRONG CORRELATION DETECTED! Source port may influence assigned port." << std::endl;
    } else if (std::abs(correlation) > 0.3) {
        std::cout << "   📊 Moderate correlation." << std::endl;
    } else {
        std::cout << "   ✅ Weak or no correlation." << std::endl;
    }
    
    // Delta analizi: assigned - source
    std::vector<int32_t> deltas;
    for (const auto& m : measurements) {
        deltas.push_back(static_cast<int32_t>(m.assigned_port) - static_cast<int32_t>(m.source_port));
    }
    
    double mean_delta = std::accumulate(deltas.begin(), deltas.end(), 0.0) / deltas.size();
    std::cout << "   Mean Delta (assigned - source): " << std::fixed << std::setprecision(1) << mean_delta << std::endl;
    
    // Sabit offset varsa göster
    std::set<int32_t> unique_deltas(deltas.begin(), deltas.end());
    if (unique_deltas.size() == 1) {
        std::cout << "   ⚠️  CONSTANT OFFSET DETECTED: " << *unique_deltas.begin() << std::endl;
    }
}

void markov_chain_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n🔗 MARKOV CHAIN ANALYSIS:" << std::endl;
    
    if (ports.size() < 3) {
        std::cout << "   Not enough data for Markov chain analysis (min 3 points)." << std::endl;
        return;
    }
    
    // 1. derece Markov chain - bir önceki porta dayalı geçiş matrisi
    std::map<std::pair<uint16_t, uint16_t>, int> transitions;
    std::map<uint16_t, int> state_counts;
    
    for (size_t i = 1; i < ports.size(); ++i) {
        uint16_t current_state = ports[i-1];
        uint16_t next_state = ports[i];
        
        transitions[{current_state, next_state}]++;
        state_counts[current_state]++;
    }
    
    std::cout << "   Transition Matrix (most frequent):" << std::endl;
    
    // En sık geçişleri göster
    std::vector<std::pair<std::pair<uint16_t, uint16_t>, int>> sorted_transitions(
        transitions.begin(), transitions.end());
    std::sort(sorted_transitions.begin(), sorted_transitions.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < std::min(size_t(10), sorted_transitions.size()); ++i) {
        const auto& trans = sorted_transitions[i];
        uint16_t from_port = trans.first.first;
        uint16_t to_port = trans.first.second;
        int count = trans.second;
        double probability = static_cast<double>(count) / state_counts[from_port];
        
        std::cout << "     " << from_port << " -> " << to_port 
                  << " (p=" << std::fixed << std::setprecision(3) << probability 
                  << ", count=" << count << ")" << std::endl;
    }
    
    // Entropi hesapla
    double total_entropy = 0.0;
    int valid_states = 0;
    
    for (const auto& state_pair : state_counts) {
        uint16_t state = state_pair.first;
        int total_from_state = state_pair.second;
        
        if (total_from_state == 0) continue;
        
        double state_entropy = 0.0;
        for (const auto& trans : transitions) {
            if (trans.first.first == state) {
                double p = static_cast<double>(trans.second) / total_from_state;
                state_entropy -= p * std::log2(p);
            }
        }
        
        total_entropy += state_entropy;
        valid_states++;
    }
    
    double avg_entropy = (valid_states > 0) ? total_entropy / valid_states : 0.0;
    std::cout << "   Average State Entropy: " << std::fixed << std::setprecision(3) 
              << avg_entropy << " bits" << std::endl;
    
    if (avg_entropy < 2.0) {
        std::cout << "   ⚠️  LOW ENTROPY - Predictable transitions detected!" << std::endl;
    } else {
        std::cout << "   ✅ High entropy - transitions appear random" << std::endl;
    }
}

void bit_plane_entropy_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n🔢 BIT PLANE ENTROPY ANALYSIS:" << std::endl;
    
    if (ports.empty()) {
        std::cout << "   No data for bit plane analysis." << std::endl;
        return;
    }
    
    // Her bit pozisyonu için entropi hesapla
    std::cout << "   Bit Position | Entropy | Status" << std::endl;
    std::cout << "   -------------|---------|-------" << std::endl;
    
    double total_entropy = 0.0;
    int weak_bits = 0;
    
    for (int bit_pos = 0; bit_pos < 16; ++bit_pos) {
        int ones = 0, zeros = 0;
        
        // Bu bit pozisyonundaki 0 ve 1'leri say
        for (uint16_t port : ports) {
            if ((port >> bit_pos) & 1) {
                ones++;
            } else {
                zeros++;
            }
        }
        
        // Entropi hesapla
        double p1 = static_cast<double>(ones) / ports.size();
        double p0 = static_cast<double>(zeros) / ports.size();
        
        double entropy = 0.0;
        if (p1 > 0) entropy -= p1 * std::log2(p1);
        if (p0 > 0) entropy -= p0 * std::log2(p0);
        
        total_entropy += entropy;
        
        std::string status = "Good";
        if (entropy < 0.5) {
            status = "WEAK";
            weak_bits++;
        } else if (entropy < 0.8) {
            status = "Fair";
        }
        
        std::cout << "   " << std::setw(12) << bit_pos 
                  << " | " << std::setw(7) << std::fixed << std::setprecision(3) << entropy
                  << " | " << status;
        
        if (p1 < 0.1 || p1 > 0.9) {
            std::cout << " (bias: " << std::setprecision(1) << (p1 * 100) << "%)";
        }
        std::cout << std::endl;
    }
    
    double avg_entropy = total_entropy / 16.0;
    std::cout << "\n   Average Bit Entropy: " << std::fixed << std::setprecision(3) 
              << avg_entropy << " bits" << std::endl;
    std::cout << "   Weak Bit Positions: " << weak_bits << "/16" << std::endl;
    
    if (weak_bits > 4) {
        std::cout << "   ⚠️  MULTIPLE WEAK BITS - Poor randomness in port assignment!" << std::endl;
    } else if (weak_bits > 0) {
        std::cout << "   📊 Some bias detected in specific bit positions" << std::endl;
    } else {
        std::cout << "   ✅ All bit positions show good entropy" << std::endl;
    }
}

void chi_square_uniformity_test(const std::vector<uint16_t>& ports) {
    std::cout << "\n📊 CHI-SQUARE UNIFORMITY TEST:" << std::endl;
    
    if (ports.size() < 10) {
        std::cout << "   Not enough data for chi-square test (min 10 points)." << std::endl;
        return;
    }
    
    // Port aralığını belirle ve bin'lere böl
    uint16_t min_port = *std::min_element(ports.begin(), ports.end());
    uint16_t max_port = *std::max_element(ports.begin(), ports.end());
    
    // Bin sayısını belirle (kare kök kuralı, min 5, max 20)
    int num_bins = std::max(5, std::min(20, static_cast<int>(std::sqrt(ports.size()))));
    double bin_width = static_cast<double>(max_port - min_port + 1) / num_bins;
    
    std::vector<int> observed(num_bins, 0);
    
    // Gözlenen frekansları hesapla
    for (uint16_t port : ports) {
        int bin_index = std::min(num_bins - 1, 
                                static_cast<int>((port - min_port) / bin_width));
        observed[bin_index]++;
    }
    
    // Beklenen frekans (uniform dağılım varsayımı)
    double expected = static_cast<double>(ports.size()) / num_bins;
    
    // Chi-square istatistiğini hesapla
    double chi_square = 0.0;
    int valid_bins = 0;
    
    std::cout << "   Bin | Range | Observed | Expected | Contribution" << std::endl;
    std::cout << "   ----|-------|----------|----------|-------------" << std::endl;
    
    for (int i = 0; i < num_bins; ++i) {
        if (expected >= 1.0) { // Chi-square testi için minimum beklenen frekans
            double contribution = (observed[i] - expected) * (observed[i] - expected) / expected;
            chi_square += contribution;
            valid_bins++;
            
            uint16_t range_start = min_port + static_cast<uint16_t>(i * bin_width);
            uint16_t range_end = (i == num_bins - 1) ? max_port : 
                                 static_cast<uint16_t>(min_port + (i + 1) * bin_width - 1);
            
            std::cout << "   " << std::setw(3) << i 
                      << " | " << std::setw(5) << range_start << "-" << std::setw(5) << range_end
                      << " | " << std::setw(8) << observed[i]
                      << " | " << std::setw(8) << std::fixed << std::setprecision(1) << expected
                      << " | " << std::setw(11) << std::setprecision(3) << contribution << std::endl;
        }
    }
    
    if (valid_bins < 2) {
        std::cout << "   Not enough valid bins for chi-square test." << std::endl;
        return;
    }
    
    int degrees_of_freedom = valid_bins - 1;
    
    std::cout << "\n   Chi-Square Statistic: " << std::fixed << std::setprecision(3) << chi_square << std::endl;
    std::cout << "   Degrees of Freedom: " << degrees_of_freedom << std::endl;
    
    // Kritik değerler (yaklaşık)
    double critical_95 = 3.84 + 2.0 * (degrees_of_freedom - 1); // Basit yaklaşım
    double critical_99 = 6.64 + 2.5 * (degrees_of_freedom - 1);
    
    std::cout << "   Critical Value (95%): ~" << std::fixed << std::setprecision(2) << critical_95 << std::endl;
    std::cout << "   Critical Value (99%): ~" << std::fixed << std::setprecision(2) << critical_99 << std::endl;
    
    if (chi_square > critical_99) {
        std::cout << "   ⚠️  HIGHLY SIGNIFICANT - Distribution is NOT uniform (p < 0.01)" << std::endl;
    } else if (chi_square > critical_95) {
        std::cout << "   📊 Significant deviation from uniformity (p < 0.05)" << std::endl;
    } else {
        std::cout << "   ✅ Distribution appears uniform (no significant deviation)" << std::endl;
    }
}

void spectral_analysis(const std::vector<uint16_t>& ports) {
    std::cout << "\n🌊 SPECTRAL ANALYSIS:" << std::endl;
    
    if (ports.size() < 8) {
        std::cout << "   Not enough data for spectral analysis (min 8 points)." << std::endl;
        return;
    }
    
    // Basit DFT tabanlı spektral analiz
    int N = ports.size();
    
    // Port değerlerini normalize et
    double mean = static_cast<double>(std::accumulate(ports.begin(), ports.end(), 0.0)) / N;
    std::vector<double> normalized(N);
    for (int i = 0; i < N; ++i) {
        normalized[i] = static_cast<double>(ports[i]) - mean;
    }
    
    // Basit DFT hesapla (sadece ilk N/2 frekans)
    std::vector<double> power_spectrum;
    
    for (int k = 1; k < N/2; ++k) { // DC bileşenini atla
        double real_sum = 0.0, imag_sum = 0.0;
        
        for (int n = 0; n < N; ++n) {
            double angle = -2.0 * M_PI * k * n / N;
            real_sum += normalized[n] * std::cos(angle);
            imag_sum += normalized[n] * std::sin(angle);
        }
        
        double power = (real_sum * real_sum + imag_sum * imag_sum) / N;
        power_spectrum.push_back(power);
    }
    
    if (power_spectrum.empty()) {
        std::cout << "   No frequency components to analyze." << std::endl;
        return;
    }
    
    // En yüksek güçlü frekansları bul
    std::vector<std::pair<int, double>> freq_power;
    for (size_t i = 0; i < power_spectrum.size(); ++i) {
        freq_power.push_back({i + 1, power_spectrum[i]});
    }
    
    std::sort(freq_power.begin(), freq_power.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::cout << "   Top Frequency Components:" << std::endl;
    std::cout << "   Freq | Period | Power | Significance" << std::endl;
    std::cout << "   -----|--------|-------|-------------" << std::endl;
    
    double total_power = std::accumulate(power_spectrum.begin(), power_spectrum.end(), 0.0);
    double avg_power = total_power / power_spectrum.size();
    
    for (size_t i = 0; i < std::min(size_t(5), freq_power.size()); ++i) {
        int freq = freq_power[i].first;
        double power = freq_power[i].second;
        double period = static_cast<double>(N) / freq;
        double significance = (avg_power > 0) ? power / avg_power : 0.0;
        
        std::cout << "   " << std::setw(4) << freq
                  << " | " << std::setw(6) << std::fixed << std::setprecision(1) << period
                  << " | " << std::setw(5) << std::setprecision(2) << power
                  << " | " << std::setw(11) << std::setprecision(2) << significance;
        
        if (significance > 3.0) {
            std::cout << " ***";
        } else if (significance > 2.0) {
            std::cout << " **";
        }
        std::cout << std::endl;
    }
    
    // Spektral düzlük ölçümü
    double geometric_mean = 1.0;
    double arithmetic_mean = avg_power;
    
    for (double power : power_spectrum) {
        if (power > 0) {
            geometric_mean *= std::pow(power, 1.0 / power_spectrum.size());
        }
    }
    
    double spectral_flatness = (arithmetic_mean > 0) ? geometric_mean / arithmetic_mean : 0.0;
    
    std::cout << "\n   Spectral Flatness: " << std::fixed << std::setprecision(4) 
              << spectral_flatness << std::endl;
    
    if (spectral_flatness > 0.8) {
        std::cout << "   ✅ Flat spectrum - appears random (white noise-like)" << std::endl;
    } else if (spectral_flatness > 0.5) {
        std::cout << "   📊 Moderately flat spectrum" << std::endl;
    } else {
        std::cout << "   ⚠️  Peaked spectrum - potential periodic patterns detected!" << std::endl;
    }
    
    // Dominant frekans kontrolü
    if (!freq_power.empty() && freq_power[0].second > 3.0 * avg_power) {
        double dominant_period = static_cast<double>(N) / freq_power[0].first;
        std::cout << "   🎯 Dominant Period Detected: ~" << std::fixed << std::setprecision(1) 
                  << dominant_period << " samples" << std::endl;
    }
}

void save_results_to_file() {
    std::cout << "\n💾 SAVE RESULTS TO FILE:" << std::endl;
    
    if (measurements.empty()) {
        std::cout << "   No data to save." << std::endl;
        return;
    }
    
    std::ofstream file("nat_analysis_results.json");
    if (!file.is_open()) {
        std::cout << "   ❌ Failed to create output file." << std::endl;
        return;
    }
    
    file << "{\n";
    file << "  \"analysis_timestamp\": " << get_timestamp_us() << ",\n";
    file << "  \"total_measurements\": " << measurements.size() << ",\n";
    file << "  \"target_server\": \"" << target_stun_server << "\",\n";
    file << "  \"measurements\": [\n";
    
    for (size_t i = 0; i < measurements.size(); ++i) {
        const auto& m = measurements[i];
        file << "    {\n";
        file << "      \"sequence\": " << m.sequence_number << ",\n";
        file << "      \"assigned_port\": " << m.assigned_port << ",\n";
        file << "      \"source_port\": " << m.source_port << ",\n";
        file << "      \"timestamp_us\": " << m.timestamp_us << ",\n";
        file << "      \"target_ip\": \"" << m.target_ip << "\",\n";
        file << "      \"success\": " << (m.success ? "true" : "false") << "\n";
        file << "    }";
        if (i < measurements.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    file.close();
    
    std::cout << "   ✅ Results saved to 'nat_analysis_results.json'" << std::endl;
}

// Port tahmin fonksiyonları
std::vector<PortPrediction> predict_next_ports(int count) {
    std::vector<PortPrediction> predictions;
    
    if (measurements.size() < 3) {
        std::cout << "⚠️  Not enough data for port prediction (min 3 measurements)" << std::endl;
        return predictions;
    }
    
    std::cout << "\n🔮 PORT PREDICTION ANALYSIS:" << std::endl;
    std::cout << "=" << std::string(40, '=') << std::endl;
    
    // Farklı yöntemlerle tahmin yap
    auto markov_predictions = predict_using_markov_chain(count);
    auto delta_predictions = predict_using_delta_patterns(count);
    auto lfsr_predictions = predict_using_lfsr_state(count);
    
    // En iyi tahminleri birleştir
    for (int i = 0; i < count; ++i) {
        PortPrediction best_prediction = {0, 0.0, "none", i + 1};
        
        // Markov chain tahmini
        if (i < static_cast<int>(markov_predictions.size()) && markov_predictions[i].confidence > best_prediction.confidence) {
            best_prediction = markov_predictions[i];
        }
        
        // Delta pattern tahmini
        if (i < static_cast<int>(delta_predictions.size()) && delta_predictions[i].confidence > best_prediction.confidence) {
            best_prediction = delta_predictions[i];
        }
        
        // LFSR tahmini
        if (i < static_cast<int>(lfsr_predictions.size()) && lfsr_predictions[i].confidence > best_prediction.confidence) {
            best_prediction = lfsr_predictions[i];
        }
        
        predictions.push_back(best_prediction);
    }
    
    std::cout << "\n📊 COMBINED PREDICTIONS:" << std::endl;
    std::cout << "Step | Port | Confidence | Method" << std::endl;
    std::cout << "-----|------|------------|--------" << std::endl;
    
    for (const auto& pred : predictions) {
        std::cout << std::setw(4) << pred.steps_ahead 
                  << " | " << std::setw(4) << pred.predicted_port
                  << " | " << std::setw(10) << std::fixed << std::setprecision(3) << pred.confidence
                  << " | " << pred.method << std::endl;
    }
    
    return predictions;
}

std::vector<PortPrediction> predict_using_markov_chain(int count) {
    std::vector<PortPrediction> predictions;
    
    if (measurements.size() < 3) return predictions;
    
    std::vector<uint16_t> ports;
    for (const auto& m : measurements) {
        ports.push_back(m.assigned_port);
    }
    
    // 1. derece Markov chain geçiş matrisi oluştur
    std::map<std::pair<uint16_t, uint16_t>, int> transitions;
    std::map<uint16_t, int> state_counts;
    
    for (size_t i = 1; i < ports.size(); ++i) {
        uint16_t current_state = ports[i-1];
        uint16_t next_state = ports[i];
        transitions[{current_state, next_state}]++;
        state_counts[current_state]++;
    }
    
    uint16_t current_port = ports.back();
    
    for (int step = 1; step <= count; ++step) {
        PortPrediction pred = {0, 0.0, "markov_chain", step};
        
        if (state_counts[current_port] > 0) {
            // En olası geçişi bul
            uint16_t best_next = 0;
            int best_count = 0;
            
            for (const auto& trans : transitions) {
                if (trans.first.first == current_port && trans.second > best_count) {
                    best_next = trans.first.second;
                    best_count = trans.second;
                }
            }
            
            if (best_count > 0) {
                pred.predicted_port = best_next;
                pred.confidence = static_cast<double>(best_count) / state_counts[current_port];
                current_port = best_next; // Sonraki adım için güncelle
            }
        }
        
        predictions.push_back(pred);
    }
    
    return predictions;
}

std::vector<PortPrediction> predict_using_delta_patterns(int count) {
    std::vector<PortPrediction> predictions;
    
    if (measurements.size() < 3) return predictions;
    
    std::vector<uint16_t> ports;
    for (const auto& m : measurements) {
        ports.push_back(m.assigned_port);
    }
    
    // Delta değerlerini hesapla
    std::vector<int32_t> deltas;
    for (size_t i = 1; i < ports.size(); ++i) {
        deltas.push_back(static_cast<int32_t>(ports[i]) - static_cast<int32_t>(ports[i-1]));
    }
    
    // En sık delta değerini bul
    std::map<int32_t, int> delta_freq;
    for (int32_t delta : deltas) {
        delta_freq[delta]++;
    }
    
    int32_t most_common_delta = 0;
    int max_freq = 0;
    for (const auto& pair : delta_freq) {
        if (pair.second > max_freq) {
            most_common_delta = pair.first;
            max_freq = pair.second;
        }
    }
    
    double confidence = static_cast<double>(max_freq) / deltas.size();
    uint16_t current_port = ports.back();
    
    for (int step = 1; step <= count; ++step) {
        PortPrediction pred;
        pred.predicted_port = static_cast<uint16_t>(std::max(0, std::min(65535, 
                                                    static_cast<int32_t>(current_port) + most_common_delta)));
        pred.confidence = confidence * std::pow(0.9, step - 1); // Güven azalır
        pred.method = "delta_pattern";
        pred.steps_ahead = step;
        
        predictions.push_back(pred);
        current_port = pred.predicted_port;
    }
    
    return predictions;
}

std::vector<PortPrediction> predict_using_lfsr_state(int count) {
    std::vector<PortPrediction> predictions;
    
    if (measurements.size() < 10) return predictions; // LFSR için daha fazla veri gerekli
    
    // Basit LFSR tahmini - bit seviyesinde pattern arama
    std::vector<uint16_t> ports;
    for (const auto& m : measurements) {
        ports.push_back(m.assigned_port);
    }
    
    // Son birkaç port değerini kullanarak basit bir pattern tahmin et
    if (ports.size() >= 3) {
        uint16_t p1 = ports[ports.size() - 3];
        uint16_t p2 = ports[ports.size() - 2];
        uint16_t p3 = ports[ports.size() - 1];
        
        // XOR tabanlı basit tahmin
        uint16_t predicted = p1 ^ p2 ^ p3;
        
        for (int step = 1; step <= count; ++step) {
            PortPrediction pred;
            pred.predicted_port = predicted;
            pred.confidence = 0.3 / step; // Düşük güven, deneysel
            pred.method = "lfsr_xor";
            pred.steps_ahead = step;
            
            predictions.push_back(pred);
            
            // Sonraki tahmin için güncelle
            predicted = p2 ^ p3 ^ predicted;
            p1 = p2; p2 = p3; p3 = predicted;
        }
    }
    
    return predictions;
}

// NAT Traversal ve P2P Hole Punching implementasyonları
bool execute_nat_type_detection() {
    std::cout << "\n🔍 NAT TYPE DETECTION:" << std::endl;
    std::cout << "=" << std::string(30, '=') << std::endl;
    
    // İki farklı STUN sunucusuna istek gönder
    std::string stun1 = "stun.l.google.com";
    std::string stun2 = "stun1.l.google.com";
    uint16_t stun_port = 19302;
    
    struct sockaddr_in stun1_addr, stun2_addr;
    memset(&stun1_addr, 0, sizeof(stun1_addr));
    memset(&stun2_addr, 0, sizeof(stun2_addr));
    
    stun1_addr.sin_family = AF_INET;
    stun1_addr.sin_port = htons(stun_port);
    inet_pton(AF_INET, "74.125.250.129", &stun1_addr.sin_addr); // Google STUN
    
    stun2_addr.sin_family = AF_INET;
    stun2_addr.sin_port = htons(stun_port);
    inet_pton(AF_INET, "74.125.250.129", &stun2_addr.sin_addr); // Aynı sunucu, farklı test
    
    // Test 1: Aynı socket ile iki farklı hedef
    int test_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_socket < 0) {
        std::cout << "   ❌ Failed to create test socket" << std::endl;
        return false;
    }
    
    uint8_t buffer[20];
    uint8_t trans_id[12];
    
    // İlk istek
    for (int i = 0; i < 12; ++i) trans_id[i] = byte_dist(rng);
    create_stun_binding_request(buffer, trans_id);
    
    sendto(test_socket, buffer, 20, 0, (struct sockaddr*)&stun1_addr, sizeof(stun1_addr));
    
    uint8_t response1[1500];
    struct sockaddr_in from_addr1;
    socklen_t from_len1 = sizeof(from_addr1);
    
    struct timeval timeout = {3, 0};
    setsockopt(test_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    ssize_t recv1 = recvfrom(test_socket, response1, sizeof(response1), 0, 
                            (struct sockaddr*)&from_addr1, &from_len1);
    
    uint16_t mapped_port1 = 0;
    if (recv1 >= 20) {
        mapped_port1 = parse_mapped_address(response1, recv1);
    }
    
    // İkinci istek (aynı socket)
    for (int i = 0; i < 12; ++i) trans_id[i] = byte_dist(rng);
    create_stun_binding_request(buffer, trans_id);
    
    sendto(test_socket, buffer, 20, 0, (struct sockaddr*)&stun2_addr, sizeof(stun2_addr));
    
    uint8_t response2[1500];
    struct sockaddr_in from_addr2;
    socklen_t from_len2 = sizeof(from_addr2);
    
    ssize_t recv2 = recvfrom(test_socket, response2, sizeof(response2), 0, 
                            (struct sockaddr*)&from_addr2, &from_len2);
    
    uint16_t mapped_port2 = 0;
    if (recv2 >= 20) {
        mapped_port2 = parse_mapped_address(response2, recv2);
    }
    
    close(test_socket);
    
    std::cout << "   First mapped port:  " << mapped_port1 << std::endl;
    std::cout << "   Second mapped port: " << mapped_port2 << std::endl;
    
    // NAT tipi analizi
    if (mapped_port1 == 0 || mapped_port2 == 0) {
        std::cout << "   🚫 NAT Type: BLOCKED or FIREWALL" << std::endl;
        return false;
    } else if (mapped_port1 == mapped_port2) {
        std::cout << "   ✅ NAT Type: FULL CONE or RESTRICTED CONE" << std::endl;
        std::cout << "   📊 Port prediction may be effective!" << std::endl;
        return true;
    } else {
        std::cout << "   ⚠️  NAT Type: SYMMETRIC NAT" << std::endl;
        std::cout << "   🎯 Port prediction attack required for traversal!" << std::endl;
        return true;
    }
}

bool execute_symmetric_nat_prediction_attack(const std::string& target_ip, uint16_t target_port) {
    std::cout << "\n🎯 SYMMETRIC NAT PREDICTION ATTACK:" << std::endl;
    std::cout << "Target: " << target_ip << ":" << target_port << std::endl;
    
    // Önce port tahminleri yap
    auto predictions = predict_next_ports(10);
    
    if (predictions.empty()) {
        std::cout << "   ❌ No port predictions available" << std::endl;
        return false;
    }
    
    // En yüksek güvenilirliğe sahip tahminleri kullan
    std::vector<uint16_t> predicted_ports;
    for (const auto& pred : predictions) {
        if (pred.confidence > 0.1) { // Minimum güven eşiği
            predicted_ports.push_back(pred.predicted_port);
        }
    }
    
    if (predicted_ports.empty()) {
        std::cout << "   ❌ No high-confidence predictions available" << std::endl;
        return false;
    }
    
    std::cout << "   📊 Using " << predicted_ports.size() << " predicted ports" << std::endl;
    
    // Hole punching dene
    return send_hole_punch_packets(target_ip, predicted_ports, 0);
}

HolePunchResult execute_hole_punching(const PeerInfo& peer) {
    HolePunchResult result = {false, 0, 0, "none", 0.0};
    auto start_time = get_timestamp_us();
    
    std::cout << "\n🕳️  HOLE PUNCHING ATTEMPT:" << std::endl;
    std::cout << "Peer: " << peer.public_ip << ":" << peer.public_port << std::endl;
    std::cout << "NAT Type: " << peer.nat_type << std::endl;
    
    // Farklı stratejiler dene
    bool success = false;
    
    // Strateji 1: Direkt bağlantı dene
    if (test_p2p_connectivity(peer.public_ip, peer.public_port)) {
        result.success = true;
        result.method_used = "direct_connection";
        success = true;
    }
    
    // Strateji 2: Port prediction ile hole punching
    if (!success && peer.nat_type == "symmetric") {
        auto predictions = predict_next_ports(5);
        std::vector<uint16_t> predicted_ports;
        
        for (const auto& pred : predictions) {
            predicted_ports.push_back(pred.predicted_port);
        }
        
        if (!predicted_ports.empty()) {
            success = execute_port_prediction_hole_punch(peer, predicted_ports);
            if (success) {
                result.method_used = "port_prediction";
            }
        }
    }
    
    // Strateji 3: Brute force hole punching (son çare)
    if (!success) {
        auto candidates = generate_port_candidates(peer.public_port, 20);
        success = send_hole_punch_packets(peer.public_ip, candidates, 0);
        if (success) {
            result.method_used = "brute_force";
        }
    }
    
    result.success = success;
    result.time_taken_ms = (get_timestamp_us() - start_time) / 1000.0;
    
    std::cout << "   Result: " << (success ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "   Method: " << result.method_used << std::endl;
    std::cout << "   Time: " << std::fixed << std::setprecision(1) << result.time_taken_ms << "ms" << std::endl;
    
    return result;
}

bool execute_port_prediction_hole_punch(const PeerInfo& peer, const std::vector<uint16_t>& predicted_ports) {
    std::cout << "   🔮 Port Prediction Hole Punch:" << std::endl;
    std::cout << "   Trying " << predicted_ports.size() << " predicted ports..." << std::endl;
    
    return send_hole_punch_packets(peer.public_ip, predicted_ports, 0);
}

bool send_hole_punch_packets(const std::string& target_ip, const std::vector<uint16_t>& target_ports, uint16_t local_port) {
    if (target_ports.empty()) return false;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Hole punch socket creation failed");
        return false;
    }
    
    // Local port bind (0 = otomatik atama)
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(local_port);
    
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("Hole punch bind failed");
        close(sock);
        return false;
    }
    
    // Hole punch mesajı
    const char* punch_msg = "HOLE_PUNCH_REQUEST";
    bool success = false;
    
    for (uint16_t target_port : target_ports) {
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        
        if (inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr) <= 0) {
            continue;
        }
        
        // Hole punch paketi gönder
        ssize_t sent = sendto(sock, punch_msg, strlen(punch_msg), 0, 
                             (struct sockaddr*)&target_addr, sizeof(target_addr));
        
        if (sent > 0) {
            std::cout << "     → " << target_ip << ":" << target_port << " (sent)" << std::endl;
            
            // Kısa yanıt bekle
            struct timeval timeout = {0, 100000}; // 100ms
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            char response[1024];
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            
            ssize_t received = recvfrom(sock, response, sizeof(response) - 1, 0, 
                                      (struct sockaddr*)&from_addr, &from_len);
            
            if (received > 0) {
                response[received] = '\0';
                std::cout << "     ← Response from " << inet_ntoa(from_addr.sin_addr) 
                          << ":" << ntohs(from_addr.sin_port) << std::endl;
                success = true;
                break;
            }
        }
        
        usleep(10000); // 10ms bekle
    }
    
    close(sock);
    return success;
}

std::vector<uint16_t> generate_port_candidates(uint16_t last_known_port, int count) {
    std::vector<uint16_t> candidates;
    
    // Son bilinen port etrafında aday portlar üret
    for (int i = -count/2; i <= count/2; ++i) {
        int candidate = static_cast<int>(last_known_port) + i;
        if (candidate > 1024 && candidate <= 65535) {
            candidates.push_back(static_cast<uint16_t>(candidate));
        }
    }
    
    // Rastgele adaylar ekle
    for (int i = candidates.size(); i < count; ++i) {
        uint16_t random_port = 1024 + (rng() % (65535 - 1024));
        candidates.push_back(random_port);
    }
    
    return candidates;
}

bool establish_p2p_connection(const PeerInfo& peer) {
    std::cout << "\n🤝 ESTABLISHING P2P CONNECTION:" << std::endl;
    
    // Hole punching dene
    HolePunchResult punch_result = execute_hole_punching(peer);
    
    if (!punch_result.success) {
        std::cout << "   ❌ Hole punching failed" << std::endl;
        return false;
    }
    
    // Bağlantı testi
    bool connected = test_p2p_connectivity(peer.public_ip, peer.public_port);
    
    if (connected) {
        std::cout << "   ✅ P2P connection established!" << std::endl;
        std::cout << "   📊 Connection method: " << punch_result.method_used << std::endl;
        return true;
    } else {
        std::cout << "   ❌ P2P connection failed" << std::endl;
        return false;
    }
}

void run_p2p_server(uint16_t listen_port) {
    std::cout << "\n🖥️  STARTING P2P SERVER on port " << listen_port << std::endl;
    
    int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        perror("Server socket creation failed");
        return;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Server bind failed");
        close(server_sock);
        return;
    }
    
    std::cout << "   📡 Listening for P2P connections..." << std::endl;
    
    char buffer[1024];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (true) {
        ssize_t received = recvfrom(server_sock, buffer, sizeof(buffer) - 1, 0,
                                  (struct sockaddr*)&client_addr, &client_len);
        
        if (received > 0) {
            buffer[received] = '\0';
            std::cout << "   📨 Received from " << inet_ntoa(client_addr.sin_addr)
                      << ":" << ntohs(client_addr.sin_port) << ": " << buffer << std::endl;
            
            // Echo yanıtı gönder
            const char* response = "P2P_CONNECTION_ACK";
            sendto(server_sock, response, strlen(response), 0,
                  (struct sockaddr*)&client_addr, client_len);
        }
    }
    
    close(server_sock);
}

bool test_p2p_connectivity(const std::string& peer_ip, uint16_t peer_port) {
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_sock < 0) return false;
    
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
        close(test_sock);
        return false;
    }
    
    const char* test_msg = "P2P_CONNECTIVITY_TEST";
    ssize_t sent = sendto(test_sock, test_msg, strlen(test_msg), 0,
                         (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    
    if (sent <= 0) {
        close(test_sock);
        return false;
    }
    
    // Yanıt bekle
    struct timeval timeout = {2, 0}; // 2 saniye
    setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    char response[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(test_sock, response, sizeof(response) - 1, 0,
                               (struct sockaddr*)&from_addr, &from_len);
    
    close(test_sock);
    return received > 0;
}

uint16_t execute_single_targeted_request(uint16_t source_port) {
    // Tek bir hedefli STUN request gönder ve sonucu döndür
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    // Source port bind
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(source_port);
    
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        // Bind başarısız olursa otomatik port atamasına izin ver
        local_addr.sin_port = 0;
        if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            close(sock);
            return 0;
        }
    }
    
    // STUN target address
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(19302);
    inet_pton(AF_INET, target_stun_server.c_str(), &target_addr.sin_addr);
    
    // STUN request oluştur
    uint8_t buffer[20];
    uint8_t trans_id[12];
    for (int i = 0; i < 12; ++i) {
        trans_id[i] = byte_dist(rng);
    }
    create_stun_binding_request(buffer, trans_id);
    
    // Gönder
    ssize_t sent = sendto(sock, buffer, 20, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    if (sent <= 0) {
        close(sock);
        return 0;
    }
    
    // Yanıt bekle
    struct timeval timeout = {2, 0}; // 2 saniye
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    uint8_t response[1500];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(sock, response, sizeof(response), 0, 
                               (struct sockaddr*)&from_addr, &from_len);
    
    close(sock);
    
    if (received >= 20) {
        STUNHeader* header = reinterpret_cast<STUNHeader*>(response);
        if (ntohs(header->type) == 0x0101) {
            return parse_mapped_address(response, received);
        }
    }
    
    return 0;
}

uint16_t execute_single_request_to_destination(uint16_t source_port, const std::string& dest_ip, uint16_t dest_port) {
    // Belirli bir source port ile belirli bir destination'a STUN request gönder
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    // Source port bind
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(source_port);
    
    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        // Bind başarısız olursa otomatik port atamasına izin ver
        local_addr.sin_port = 0;
        if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            close(sock);
            return 0;
        }
    }
    
    // Destination address
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(dest_port);
    
    if (inet_pton(AF_INET, dest_ip.c_str(), &target_addr.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    
    // STUN request oluştur
    uint8_t buffer[20];
    uint8_t trans_id[12];
    for (int i = 0; i < 12; ++i) {
        trans_id[i] = byte_dist(rng);
    }
    create_stun_binding_request(buffer, trans_id);
    
    // Gönder
    ssize_t sent = sendto(sock, buffer, 20, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    if (sent <= 0) {
        close(sock);
        return 0;
    }
    
    // Yanıt bekle
    struct timeval timeout = {3, 0}; // 3 saniye (farklı server'lar için daha uzun)
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    uint8_t response[1500];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(sock, response, sizeof(response), 0, 
                               (struct sockaddr*)&from_addr, &from_len);
    
    close(sock);
    
    if (received >= 20) {
        STUNHeader* header = reinterpret_cast<STUNHeader*>(response);
        if (ntohs(header->type) == 0x0101) {
            return parse_mapped_address(response, received);
        }
    }
    
    return 0; // Timeout veya hata
}

// Birthday-Paradox ve Gelişmiş NAT Traversal Implementasyonları

std::vector<STUNTarget> select_multi_stun_targets(int count) {
    std::vector<STUNTarget> targets;
    
    // Farklı otonom sistemlerde bilinen STUN sunucuları
    std::vector<std::pair<std::string, std::string>> known_stuns = {
        {"stun.l.google.com", "74.125.250.129"},
        {"stun1.l.google.com", "74.125.250.129"},
        {"stun2.l.google.com", "74.125.250.129"},
        {"stun3.l.google.com", "74.125.250.129"},
        {"stun4.l.google.com", "74.125.250.129"},
        {"stun.cloudflare.com", "1.1.1.1"},
        {"stun.nextcloud.com", "95.217.144.14"},
        {"stun.antisip.com", "217.10.68.152"}
    };
    
    std::cout << "\n🎯 SELECTING MULTI-STUN TARGETS:" << std::endl;
    
    for (int i = 0; i < std::min(count, static_cast<int>(known_stuns.size())); ++i) {
        STUNTarget target;
        target.hostname = known_stuns[i].first;
        target.ip = known_stuns[i].second;
        target.port = 19302;
        target.rtt_avg = 0.0;
        target.active = true;
        
        targets.push_back(target);
        std::cout << "   📡 Target " << (i+1) << ": " << target.hostname 
                  << " (" << target.ip << ":" << target.port << ")" << std::endl;
    }
    
    return targets;
}

BirthdayParadoxPlan calculate_birthday_paradox_plan(int n_space, double target_prob) {
    BirthdayParadoxPlan plan;
    
    std::cout << "\n🎂 BIRTHDAY-PARADOX CALCULATION:" << std::endl;
    std::cout << "Port space size (N): " << n_space << std::endl;
    std::cout << "Target probability: " << std::fixed << std::setprecision(3) << target_prob << std::endl;
    
    // m ≈ sqrt(N * ln(1/(1-P)))
    double ln_factor = std::log(1.0 / (1.0 - target_prob));
    int m_optimal = static_cast<int>(std::ceil(std::sqrt(n_space * ln_factor)));
    
    // Daha kesin hesaplama için iteratif yaklaşım
    double actual_prob = 0.0;
    int m_adjusted = m_optimal;
    
    for (int iterations = 0; iterations < 10; ++iterations) {
        // P ≈ 1 - e^(-m²/N)
        actual_prob = 1.0 - std::exp(-static_cast<double>(m_adjusted * m_adjusted) / n_space);
        
        if (actual_prob >= target_prob) break;
        m_adjusted += static_cast<int>(std::ceil(m_adjusted * 0.1)); // %10 artır
    }
    
    plan.m_optimal = m_adjusted;
    plan.n_space = n_space;
    plan.success_probability = actual_prob;
    
    // Stealth batch'leri hesapla (azalan adımlarla)
    int remaining = m_adjusted;
    double batch_factor = 0.4; // İlk batch %40
    
    while (remaining > 0) {
        int batch_size = std::max(10, static_cast<int>(remaining * batch_factor));
        batch_size = std::min(batch_size, remaining);
        plan.stealth_batches.push_back(batch_size);
        remaining -= batch_size;
        batch_factor *= 0.85; // Her batch %15 daha küçük
    }
    
    plan.use_phase_lock = true;
    plan.phase_period_ms = 5; // 5ms faz periyodu varsayılan
    
    std::cout << "📊 Optimal shot count (m): " << plan.m_optimal << std::endl;
    std::cout << "📊 Actual success probability: " << std::fixed << std::setprecision(4) 
              << plan.success_probability << std::endl;
    std::cout << "📊 Stealth batches: ";
    for (size_t i = 0; i < plan.stealth_batches.size(); ++i) {
        std::cout << plan.stealth_batches[i];
        if (i < plan.stealth_batches.size() - 1) std::cout << " + ";
    }
    std::cout << " = " << plan.m_optimal << std::endl;
    
    // Farklı NAT tipleri için tahminler
    std::cout << "\n📋 SCENARIO ESTIMATES:" << std::endl;
    
    std::vector<std::pair<std::string, int>> scenarios = {
        {"Mobile Network", 800},
        {"Home Network", 5000},
        {"Corporate Network", 30000}
    };
    
    for (const auto& scenario : scenarios) {
        int m_scenario = static_cast<int>(std::ceil(2.146 * std::sqrt(scenario.second)));
        std::cout << "   " << scenario.first << " (N=" << scenario.second 
                  << "): ~" << m_scenario << " shots needed" << std::endl;
    }
    
    return plan;
}

EntropyHeatmap measure_phase_multi_stun(const std::vector<STUNTarget>& targets, int burst_size) {
    std::cout << "\n🔬 MULTI-STUN ENTROPY MEASUREMENT PHASE:" << std::endl;
    std::cout << "Targets: " << targets.size() << ", Burst size per target: " << burst_size << std::endl;
    
    EntropyHeatmap heatmap;
    std::vector<PacketMeasurement> all_measurements;
    
    // Her STUN hedefi için paralel burst
    for (const auto& target : targets) {
        std::cout << "\n📡 Measuring target: " << target.hostname << std::endl;
        
        // Geçici olarak global değişkenleri güncelle
        std::string old_server = target_stun_server;
        target_stun_server = target.ip;
        
        // Burst çalıştır
        if (execute_high_performance_burst(burst_size)) {
            // Sonuçları topla
            for (const auto& measurement : measurements) {
                PacketMeasurement tagged_measurement = measurement;
                tagged_measurement.target_ip = target.ip;
                all_measurements.push_back(tagged_measurement);
            }
            std::cout << "   ✅ Collected " << measurements.size() << " measurements" << std::endl;
        }
        
        target_stun_server = old_server;
        measurements.clear(); // Bir sonraki hedef için temizle
    }
    
    std::cout << "\n📊 Total measurements collected: " << all_measurements.size() << std::endl;
    
    if (all_measurements.empty()) {
        std::cout << "❌ No measurements for entropy analysis" << std::endl;
        return heatmap;
    }
    
    // Port aralığını belirle
    std::vector<uint16_t> all_ports;
    for (const auto& m : all_measurements) {
        all_ports.push_back(m.assigned_port);
    }
    
    uint16_t min_port = *std::min_element(all_ports.begin(), all_ports.end());
    uint16_t max_port = *std::max_element(all_ports.begin(), all_ports.end());
    
    std::cout << "Port range: " << min_port << " - " << max_port 
              << " (span: " << (max_port - min_port) << ")" << std::endl;
    
    // Bin'lere ayır (128 bin)
    int num_bins = 128;
    int bin_size = std::max(1, (max_port - min_port + 1) / num_bins);
    
    heatmap.bins.resize(num_bins);
    
    for (int i = 0; i < num_bins; ++i) {
        PortBin& bin = heatmap.bins[i];
        bin.start_port = min_port + i * bin_size;
        bin.end_port = std::min(static_cast<uint16_t>(bin.start_port + bin_size - 1), max_port);
        bin.frequency = 0;
        bin.entropy = 0.0;
        bin.time_correlation = 0.0;
        bin.is_hot = false;
    }
    
    // Frekansları hesapla
    for (uint16_t port : all_ports) {
        int bin_index = std::min(num_bins - 1, (port - min_port) / bin_size);
        heatmap.bins[bin_index].frequency++;
    }
    
    // Entropi hesapla
    int total_ports = all_ports.size();
    for (auto& bin : heatmap.bins) {
        if (bin.frequency > 0) {
            double p = static_cast<double>(bin.frequency) / total_ports;
            bin.entropy = -p * std::log2(p);
        }
    }
    
    // Sıcak bin'leri belirle (top %20)
    std::vector<std::pair<int, int>> bin_freq_pairs;
    for (size_t i = 0; i < heatmap.bins.size(); ++i) {
        bin_freq_pairs.push_back({heatmap.bins[i].frequency, static_cast<int>(i)});
    }
    
    std::sort(bin_freq_pairs.rbegin(), bin_freq_pairs.rend());
    
    int hot_bin_count = std::max(1, num_bins / 5); // Top %20
    int effective_ports = 0;
    
    for (int i = 0; i < hot_bin_count && i < static_cast<int>(bin_freq_pairs.size()); ++i) {
        int bin_idx = bin_freq_pairs[i].second;
        heatmap.bins[bin_idx].is_hot = true;
        effective_ports += bin_size;
    }
    
    heatmap.n_effective = effective_ports;
    heatmap.effective_range_start = min_port;
    heatmap.effective_range_end = max_port;
    heatmap.concentration_ratio = static_cast<double>(effective_ports) / (max_port - min_port + 1);
    
    std::cout << "\n🔥 ENTROPY HEATMAP RESULTS:" << std::endl;
    std::cout << "Hot bins: " << hot_bin_count << "/" << num_bins << std::endl;
    std::cout << "Effective port space: " << heatmap.n_effective 
              << " (concentration: " << std::fixed << std::setprecision(2) 
              << (heatmap.concentration_ratio * 100) << "%)" << std::endl;
    
    // En sıcak bin'leri göster
    std::cout << "Top hot bins:" << std::endl;
    for (int i = 0; i < std::min(5, hot_bin_count); ++i) {
        int bin_idx = bin_freq_pairs[i].second;
        const auto& bin = heatmap.bins[bin_idx];
        std::cout << "   🔥 " << bin.start_port << "-" << bin.end_port 
                  << ": " << bin.frequency << " hits ("
                  << std::fixed << std::setprecision(1) 
                  << (100.0 * bin.frequency / total_ports) << "%)" << std::endl;
    }
    
    return heatmap;
}

std::vector<uint16_t> generate_weighted_port_candidates(const EntropyHeatmap& heatmap, int count) {
    std::vector<uint16_t> candidates;
    
    if (heatmap.bins.empty()) {
        // Fallback: rastgele portlar
        for (int i = 0; i < count; ++i) {
            candidates.push_back(1024 + (rng() % (65535 - 1024)));
        }
        return candidates;
    }
    
    // Ağırlıklı örnekleme: sıcak bin'lerden daha fazla
    std::vector<std::pair<double, int>> bin_weights;
    
    for (size_t i = 0; i < heatmap.bins.size(); ++i) {
        const auto& bin = heatmap.bins[i];
        double weight = bin.is_hot ? (bin.frequency * 2.0) : bin.frequency;
        if (weight > 0) {
            bin_weights.push_back({weight, static_cast<int>(i)});
        }
    }
    
    if (bin_weights.empty()) {
        std::cout << "⚠️  No weighted bins available, using uniform sampling" << std::endl;
        for (int i = 0; i < count; ++i) {
            candidates.push_back(heatmap.effective_range_start + 
                               (rng() % (heatmap.effective_range_end - heatmap.effective_range_start + 1)));
        }
        return candidates;
    }
    
    // Kümülatif ağırlık hesapla
    double total_weight = 0.0;
    for (const auto& pair : bin_weights) {
        total_weight += pair.first;
    }
    
    // Weighted sampling
    for (int i = 0; i < count; ++i) {
        double random_weight = (static_cast<double>(rng()) / rng.max()) * total_weight;
        double cumulative = 0.0;
        
        for (const auto& pair : bin_weights) {
            cumulative += pair.first;
            if (cumulative >= random_weight) {
                const auto& bin = heatmap.bins[pair.second];
                uint16_t port = bin.start_port + (rng() % (bin.end_port - bin.start_port + 1));
                candidates.push_back(port);
                break;
            }
        }
    }
    
    std::cout << "🎯 Generated " << candidates.size() << " weighted port candidates" << std::endl;
    return candidates;
}

PRNGModel attempt_prng_seed_extraction(const std::vector<PacketMeasurement>& measurements) {
    PRNGModel model;
    model.type = "ENTROPY_ONLY";
    model.confidence = 0.0;
    model.prediction_accuracy = 0;
    
    if (measurements.size() < 10) {
        std::cout << "\n🔍 PRNG SEED EXTRACTION: Not enough data" << std::endl;
        return model;
    }
    
    std::cout << "\n🔍 PRNG SEED EXTRACTION ATTEMPT:" << std::endl;
    
    std::vector<uint16_t> ports;
    std::vector<uint64_t> timestamps;
    
    for (const auto& m : measurements) {
        ports.push_back(m.assigned_port);
        timestamps.push_back(m.timestamp_us);
    }
    
    // Test 1: Linear Congruential Generator (LCG) pattern
    std::cout << "🔬 Testing LCG patterns..." << std::endl;
    
    // Basit delta analizi
    std::vector<int32_t> deltas;
    for (size_t i = 1; i < ports.size(); ++i) {
        deltas.push_back(static_cast<int32_t>(ports[i]) - static_cast<int32_t>(ports[i-1]));
    }
    
    // Delta'ların tutarlılığını kontrol et
    std::map<int32_t, int> delta_freq;
    for (int32_t delta : deltas) {
        delta_freq[delta]++;
    }
    
    // En sık delta
    int max_freq = 0;
    int32_t dominant_delta = 0;
    for (const auto& pair : delta_freq) {
        if (pair.second > max_freq) {
            max_freq = pair.second;
            dominant_delta = pair.first;
        }
    }
    
    double delta_consistency = static_cast<double>(max_freq) / deltas.size();
    
    std::cout << "   Dominant delta: " << dominant_delta 
              << " (consistency: " << std::fixed << std::setprecision(3) 
              << delta_consistency << ")" << std::endl;
    
    if (delta_consistency > 0.3) {
        model.type = "LINEAR_PATTERN";
        model.confidence = delta_consistency;
        model.parameters = {static_cast<uint32_t>(std::abs(dominant_delta))};
        model.predicted_range_start = ports.back();
        model.predicted_range_end = static_cast<uint16_t>(
            std::max(1024, std::min(65535, static_cast<int>(ports.back()) + dominant_delta * 10)));
        model.prediction_accuracy = static_cast<int>(delta_consistency * 100);
        
        std::cout << "   ✅ Linear pattern detected!" << std::endl;
        std::cout << "   📊 Predicted next range: " << model.predicted_range_start 
                  << " - " << model.predicted_range_end << std::endl;
    } else {
        std::cout << "   ❌ No strong linear pattern found" << std::endl;
    }
    
    // Test 2: Zaman korelasyonu
    std::cout << "🔬 Testing time correlation..." << std::endl;
    
    if (timestamps.size() >= ports.size()) {
        // Port ve zaman arasında korelasyon hesapla
        double sum_time = 0, sum_port = 0, sum_time_port = 0, sum_time2 = 0, sum_port2 = 0;
        int n = std::min(timestamps.size(), ports.size());
        
        for (int i = 0; i < n; ++i) {
            double t = static_cast<double>(timestamps[i] / 1000000); // saniyeye çevir
            double p = static_cast<double>(ports[i]);
            
            sum_time += t;
            sum_port += p;
            sum_time_port += t * p;
            sum_time2 += t * t;
            sum_port2 += p * p;
        }
        
        double correlation = (n * sum_time_port - sum_time * sum_port) /
                           std::sqrt((n * sum_time2 - sum_time * sum_time) * 
                                   (n * sum_port2 - sum_port * sum_port));
        
        std::cout << "   Time-port correlation: " << std::fixed << std::setprecision(4) 
                  << correlation << std::endl;
        
        if (std::abs(correlation) > 0.5) {
            if (model.confidence < std::abs(correlation)) {
                model.type = "TIME_BASED";
                model.confidence = std::abs(correlation);
                model.prediction_accuracy = static_cast<int>(std::abs(correlation) * 100);
            }
            std::cout << "   ⚠️  Strong time correlation detected!" << std::endl;
        }
    }
    
    return model;
}

GlobalClockSync initialize_global_clock_sync() {
    GlobalClockSync sync;
    
    // Basit NTP offset tahmini (gerçek implementasyonda NTP query yapılır)
    auto now = std::chrono::high_resolution_clock::now();
    sync.ntp_offset_us = 0; // Placeholder
    sync.ptp_offset_us = 0; // Placeholder
    sync.is_synchronized = false; // Gerçek NTP sync olmadan false
    sync.accuracy_us = 1000.0; // 1ms accuracy varsayılan
    
    std::cout << "\n⏰ GLOBAL CLOCK SYNC:" << std::endl;
    std::cout << "   Status: " << (sync.is_synchronized ? "SYNCHRONIZED" : "LOCAL_ONLY") << std::endl;
    std::cout << "   Accuracy: ±" << sync.accuracy_us << " µs" << std::endl;
    
    return sync;
}

void align_to_phase_period(int phase_period_ms) {
    if (phase_period_ms <= 0) return;
    
    auto now = std::chrono::high_resolution_clock::now();
    auto us_since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    
    int phase_period_us = phase_period_ms * 1000;
    int phase_offset = us_since_epoch % phase_period_us;
    int sleep_time = phase_period_us - phase_offset;
    
    if (sleep_time > 0 && sleep_time < phase_period_us) {
        std::cout << "🔄 Phase alignment: sleeping " << sleep_time << " µs" << std::endl;
        usleep(sleep_time);
    }
}

bool detect_collision_promiscuous() {
    // Placeholder: Gerçek implementasyonda promiscuous mode ile
    // network interface'den gelen paketleri dinler ve collision sinyali arar
    
    std::cout << "👂 Promiscuous collision detection: NOT IMPLEMENTED" << std::endl;
    return false;
}

bool execute_stealth_burst_attack(const std::vector<uint16_t>& port_candidates, 
                                 const std::string& target_ip, 
                                 const BirthdayParadoxPlan& plan) {
    std::cout << "\n🥷 STEALTH BURST ATTACK:" << std::endl;
    std::cout << "Target: " << target_ip << std::endl;
    std::cout << "Total shots planned: " << plan.m_optimal << std::endl;
    std::cout << "Batch strategy: ";
    for (size_t i = 0; i < plan.stealth_batches.size(); ++i) {
        std::cout << plan.stealth_batches[i];
        if (i < plan.stealth_batches.size() - 1) std::cout << " → ";
    }
    std::cout << std::endl;
    
    bool collision_detected = false;
    int shots_fired = 0;
    
    for (size_t batch_idx = 0; batch_idx < plan.stealth_batches.size() && !collision_detected; ++batch_idx) {
        int batch_size = plan.stealth_batches[batch_idx];
        
        std::cout << "\n🎯 Batch " << (batch_idx + 1) << "/" << plan.stealth_batches.size() 
                  << ": " << batch_size << " shots" << std::endl;
        
        // Faz hizalama
        if (plan.use_phase_lock) {
            align_to_phase_period(plan.phase_period_ms);
        }
        
        // Bu batch için port seçimi
        std::vector<uint16_t> batch_ports;
        for (int i = 0; i < batch_size && shots_fired + i < static_cast<int>(port_candidates.size()); ++i) {
            batch_ports.push_back(port_candidates[shots_fired + i]);
        }
        
        if (batch_ports.empty()) {
            std::cout << "   ⚠️  No more port candidates available" << std::endl;
            break;
        }
        
        // Jitter ekleyerek burst gönder
        auto batch_start = get_timestamp_us();
        
        for (uint16_t port : batch_ports) {
            // Mikro jitter (50-250 µs)
            int jitter_us = 50 + (rng() % 200);
            usleep(jitter_us);
            
            // Hole punch paketi gönder
            std::vector<uint16_t> single_port = {port};
            send_hole_punch_packets(target_ip, single_port, 0);
            
            shots_fired++;
            
            // Erken collision detection
            if (detect_collision_promiscuous()) {
                collision_detected = true;
                std::cout << "   🎉 COLLISION DETECTED at shot " << shots_fired << "!" << std::endl;
                break;
            }
        }
        
        auto batch_end = get_timestamp_us();
        double batch_duration_ms = (batch_end - batch_start) / 1000.0;
        
        std::cout << "   📊 Batch completed: " << batch_ports.size() << " shots in " 
                  << std::fixed << std::setprecision(1) << batch_duration_ms << " ms" << std::endl;
        
        if (!collision_detected && batch_idx < plan.stealth_batches.size() - 1) {
            // Batch'ler arası bekleme (IDS/Firewall detection'ı azaltmak için)
            int inter_batch_delay_ms = 100 + (rng() % 200); // 100-300ms
            std::cout << "   ⏳ Inter-batch delay: " << inter_batch_delay_ms << " ms" << std::endl;
            usleep(inter_batch_delay_ms * 1000);
        }
    }
    
    std::cout << "\n📈 STEALTH BURST SUMMARY:" << std::endl;
    std::cout << "Total shots fired: " << shots_fired << "/" << plan.m_optimal << std::endl;
    std::cout << "Success: " << (collision_detected ? "YES" : "NO") << std::endl;
    
    return collision_detected;
}

bool execute_simultaneous_punch_with_birthday_paradox(const BirthdayParadoxPlan& plan, 
                                                     const EntropyHeatmap& heatmap,
                                                     const PeerInfo& peer) {
    std::cout << "\n🎯 SIMULTANEOUS BIRTHDAY-PARADOX PUNCH:" << std::endl;
    std::cout << "Peer: " << peer.public_ip << ":" << peer.public_port << std::endl;
    std::cout << "Strategy: " << plan.m_optimal << " shots with " 
              << std::fixed << std::setprecision(2) << (plan.success_probability * 100) 
              << "% success probability" << std::endl;
    
    // Ağırlıklı port adayları üret
    auto port_candidates = generate_weighted_port_candidates(heatmap, plan.m_optimal);
    
    if (port_candidates.empty()) {
        std::cout << "❌ No port candidates generated" << std::endl;
        return false;
    }
    
    // Global clock sync
    auto clock_sync = initialize_global_clock_sync();
    
    // Stealth burst attack
    bool success = execute_stealth_burst_attack(port_candidates, peer.public_ip, plan);
    
    return success;
}

void execute_master_nat_traversal_strategy() {
    std::cout << "\n🚀 MASTER NAT TRAVERSAL STRATEGY" << std::endl;
    std::cout << "=" << std::string(60, '=') << std::endl;
    
    // S0: Ölçüm → Çoklu-STUN paralel burst + saat damgalama
    std::cout << "\n📋 PHASE S0: MEASUREMENT" << std::endl;
    auto targets = select_multi_stun_targets(4);
    auto heatmap = measure_phase_multi_stun(targets, 128);
    
    if (heatmap.bins.empty()) {
        std::cout << "❌ Measurement phase failed" << std::endl;
        return;
    }
    
    // S1: Seed-fit? → "Yeterli doğrulukta" bir PRNG modeli bulunursa S2-Keskin; yoksa S3-Entropi
    std::cout << "\n📋 PHASE S1: PRNG SEED EXTRACTION" << std::endl;
    
    // Tüm measurements'ları topla
    std::vector<PacketMeasurement> all_measurements;
    // (Bu örnekte measurements global değişkeninden alıyoruz, gerçekte heatmap measurement'larından gelir)
    for (const auto& m : measurements) {
        all_measurements.push_back(m);
    }
    
    auto prng_model = attempt_prng_seed_extraction(all_measurements);
    
    bool use_keen_prediction = (prng_model.confidence > 0.4 && prng_model.prediction_accuracy > 40);
    int effective_n;
    
    if (use_keen_prediction) {
        // S2: Keskin pencere
        std::cout << "\n📋 PHASE S2: KEEN PREDICTION" << std::endl;
        effective_n = std::abs(prng_model.predicted_range_end - prng_model.predicted_range_start);
        std::cout << "🎯 Using PRNG-based prediction, N_keen = " << effective_n << std::endl;
    } else {
        // S3: Isı haritası
        std::cout << "\n📋 PHASE S3: ENTROPY HEATMAP" << std::endl;
        effective_n = heatmap.n_effective;
        std::cout << "🔥 Using entropy heatmap, N_eff = " << effective_n << std::endl;
    }
    
    // Birthday-paradox planı hesapla
    auto bp_plan = calculate_birthday_paradox_plan(effective_n, 0.99);
    
    // S4: Başarı? → Eşleşme sinyali alındıysa DONE
    std::cout << "\n📋 PHASE S4: SIMULTANEOUS PUNCH" << std::endl;
    
    // Demo peer bilgisi
    PeerInfo demo_peer;
    demo_peer.public_ip = "8.8.8.8";
    demo_peer.public_port = 12345;
    demo_peer.nat_type = "symmetric";
    demo_peer.last_seen = get_timestamp_us();
    
    bool success = execute_simultaneous_punch_with_birthday_paradox(bp_plan, heatmap, demo_peer);
    
    if (success) {
        std::cout << "\n✅ NAT TRAVERSAL SUCCESS!" << std::endl;
        std::cout << "🎉 P2P connection established using birthday-paradox strategy" << std::endl;
    } else {
        std::cout << "\n📋 PHASE S5: FALLBACK STRATEGY" << std::endl;
        std::cout << "❌ Birthday-paradox failed, implementing fallback..." << std::endl;
        std::cout << "💡 Fallback options:" << std::endl;
        std::cout << "   1. Observer-assisted port collection" << std::endl;
        std::cout << "   2. Short-lived mini-TURN relay" << std::endl;
        std::cout << "   3. Phase re-lock and retry" << std::endl;
        std::cout << "   4. Adjust entropy window and retry" << std::endl;
    }
    
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Master strategy execution completed." << std::endl;
}

bool execute_targeted_port_attack(uint16_t target_port) {
    std::cout << "\n🎯 TARGETED PORT ATTACK:" << std::endl;
    std::cout << "Target Port: " << target_port << std::endl;
    
    if (measurements.empty()) {
        std::cout << "❌ No measurement data available" << std::endl;
        return false;
    }
    
    // Mevcut port tahminleri yap
    auto predictions = predict_next_ports(20);
    
    std::cout << "\n🔮 PORT PREDICTION ANALYSIS:" << std::endl;
    std::cout << "Checking if target port " << target_port << " is predictable..." << std::endl;
    
    // Hedef portun tahmin edilen portlar arasında olup olmadığını kontrol et
    bool found_in_predictions = false;
    double best_confidence = 0.0;
    std::string best_method = "none";
    
    for (const auto& pred : predictions) {
        if (pred.predicted_port == target_port) {
            found_in_predictions = true;
            if (pred.confidence > best_confidence) {
                best_confidence = pred.confidence;
                best_method = pred.method;
            }
            std::cout << "   ✅ Target found in predictions! Method: " << pred.method 
                      << ", Confidence: " << std::fixed << std::setprecision(3) << pred.confidence << std::endl;
        }
    }
    
    if (!found_in_predictions) {
        std::cout << "   ⚠️  Target port not found in direct predictions" << std::endl;
        
        // Hedef portun mevcut port aralığında olup olmadığını kontrol et
        std::vector<uint16_t> observed_ports;
        for (const auto& m : measurements) {
            observed_ports.push_back(m.assigned_port);
        }
        
        uint16_t min_port = *std::min_element(observed_ports.begin(), observed_ports.end());
        uint16_t max_port = *std::max_element(observed_ports.begin(), observed_ports.end());
        
        if (target_port >= min_port && target_port <= max_port) {
            std::cout << "   📊 Target port is within observed range [" << min_port << "-" << max_port << "]" << std::endl;
        } else {
            std::cout << "   ❌ Target port is outside observed range [" << min_port << "-" << max_port << "]" << std::endl;
            std::cout << "   🎯 Attempting targeted manipulation anyway..." << std::endl;
        }
    }
    
    // Strateji 0: Bilinen deterministik mapping'leri kontrol et
    std::cout << "\n🔧 STRATEGY 0: Known deterministic mappings" << std::endl;
    
    // Gözlemlenen tutarlı mapping'ler
    std::map<uint16_t, uint16_t> known_mappings = {
        {10012, 20138}, {10015, 17811}, {10020, 19098}, 
        {10025, 19947}, {10030, 20270}, {10039, 21239},
        {10041, 21353}, {10022, 20122}, {10013, 20909},
        {10047, 18341}, {10048, 18708}, {10011, 18987},
        {10010, 18028}, {10023, 20369}
    };
    
    for (const auto& mapping : known_mappings) {
        if (mapping.second == target_port) {
            std::cout << "   🎯 DIRECT HIT! Source " << mapping.first 
                      << " maps to target " << target_port << std::endl;
            
            uint16_t result = execute_single_targeted_request(mapping.first);
            if (result == target_port) {
                std::cout << "   🎉 SUCCESS! Deterministic mapping confirmed!" << std::endl;
                std::cout << "   📊 Source port " << mapping.first 
                          << " → Target port " << target_port << std::endl;
                return true;
            } else {
                std::cout << "   📊 Expected " << target_port << " but got " << result << std::endl;
            }
        }
    }
    
    std::cout << "   No direct deterministic mapping found for target " << target_port << std::endl;

    // Strateji 1: Hedef porta yakın portları dene
    std::cout << "\n🔧 STRATEGY 1: Proximity-based targeting" << std::endl;
    
    std::vector<uint16_t> proximity_candidates;
    for (int offset = -10; offset <= 10; ++offset) {
        int candidate = static_cast<int>(target_port) + offset;
        if (candidate > 1024 && candidate <= 65535) {
            proximity_candidates.push_back(static_cast<uint16_t>(candidate));
        }
    }
    
    std::cout << "   Trying " << proximity_candidates.size() << " ports around target..." << std::endl;
    
    // Test proximity candidates
    bool proximity_success = false;
    for (uint16_t candidate : proximity_candidates) {
        uint16_t result = execute_single_targeted_request(candidate);
        if (result == target_port) {
            std::cout << "   🎉 SUCCESS! Proximity attack worked!" << std::endl;
            std::cout << "   📊 Source port " << candidate << " mapped to target port " << target_port << std::endl;
            proximity_success = true;
            break;
        } else if (result > 0) {
            std::cout << "   📊 Source " << candidate << " -> " << result 
                      << " (distance: " << std::abs(static_cast<int>(result) - static_cast<int>(target_port)) << ")" << std::endl;
        }
    }
    
    if (proximity_success) {
        return true;
    }
    
    // Strateji 2: Pattern-based targeting
    std::cout << "\n🔧 STRATEGY 2: Pattern-based targeting" << std::endl;
    
    if (found_in_predictions && best_confidence > 0.2) {
        std::cout << "   Using " << best_method << " method with confidence " 
                  << std::fixed << std::setprecision(3) << best_confidence << std::endl;
        
        // En iyi tahmin methodunu kullanarak daha fazla deneme yap
        if (best_method == "delta_pattern") {
            std::cout << "   Using delta pattern method..." << std::endl;
            // Delta pattern tabanlı arama
            std::vector<uint16_t> delta_candidates;
            for (const auto& pred : predictions) {
                if (pred.method == "delta_pattern") {
                    delta_candidates.push_back(pred.predicted_port);
                }
            }
            
            for (uint16_t candidate : delta_candidates) {
                uint16_t result = execute_single_targeted_request(candidate);
                if (result == target_port) {
                    std::cout << "   🎉 Delta pattern success!" << std::endl;
                    return true;
                }
            }
        } else if (best_method == "markov_chain") {
            std::cout << "   Using markov chain method..." << std::endl;
            // Markov chain tabanlı arama
            for (int attempt = 0; attempt < 30; ++attempt) {
                uint16_t candidate = 10000 + attempt + (rng() % 1000);
                uint16_t result = execute_single_targeted_request(candidate);
                if (result == target_port) {
                    std::cout << "   🎉 Markov chain success!" << std::endl;
                    return true;
                }
            }
        }
    }
    
    // Strateji 3: Brute force in predicted range
    std::cout << "\n🔧 STRATEGY 3: Intelligent brute force" << std::endl;
    
    // En yakın tahmin edilen portları bul
    std::vector<std::pair<uint16_t, int>> port_distances;
    for (const auto& pred : predictions) {
        int distance = std::abs(static_cast<int>(pred.predicted_port) - static_cast<int>(target_port));
        port_distances.push_back({pred.predicted_port, distance});
    }
    
    std::sort(port_distances.begin(), port_distances.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    if (!port_distances.empty()) {
        uint16_t closest_predicted = port_distances[0].first;
        int min_distance = port_distances[0].second;
        
        std::cout << "   Closest predicted port: " << closest_predicted 
                  << " (distance: " << min_distance << ")" << std::endl;
        
        if (min_distance < 1000) {
            // Yakın tahmin varsa, o bölgede yoğunlaşalım
            std::vector<uint16_t> focused_candidates;
            uint16_t start = std::min(closest_predicted, target_port);
            uint16_t end = std::max(closest_predicted, target_port);
            
            for (uint16_t port = start; port <= end && focused_candidates.size() < 100; ++port) {
                focused_candidates.push_back(port);
            }
            
            std::cout << "   Focused search in range [" << start << "-" << end << "] with " 
                      << focused_candidates.size() << " candidates" << std::endl;
            
            for (uint16_t candidate : focused_candidates) {
                uint16_t result = execute_single_targeted_request(candidate);
                if (result == target_port) {
                    std::cout << "   🎉 SUCCESS! Focused search worked!" << std::endl;
                    std::cout << "   📊 Source port " << candidate << " mapped to target port " << target_port << std::endl;
                    return true;
                }
            }
        }
    }
    
    // Strateji 4: Son çare - rastgele deneme
    std::cout << "\n🔧 STRATEGY 4: Last resort random sampling" << std::endl;
    std::cout << "   Attempting 100 random source ports..." << std::endl;
    
    for (int i = 0; i < 100; ++i) {
        uint16_t random_source = 10000 + (rng() % 50000);
        uint16_t result = execute_single_targeted_request(random_source);
        
        if (result == target_port) {
            std::cout << "   🎉 SUCCESS! Random sampling worked!" << std::endl;
            std::cout << "   📊 Source port " << random_source << " mapped to target port " << target_port << std::endl;
            return true;
        }
        
        if (i % 20 == 0) {
            std::cout << "   📊 Tried " << (i+1) << "/100 random attempts..." << std::endl;
        }
    }
    
    std::cout << "\n❌ All targeting strategies failed for port " << target_port << std::endl;
    std::cout << "💡 Recommendations:" << std::endl;
    std::cout << "   1. Try birthday-paradox approach with peer coordination" << std::endl;
    std::cout << "   2. Increase measurement sample size for better predictions" << std::endl;
    std::cout << "   3. Use multi-STUN entropy analysis for better targeting" << std::endl;
    
    return false;
}

// main fonksiyonu, programın giriş noktası
int main(int argc, char* argv[]) {
    // Varsayılan STUN sunucusu ve portu
    std::string stun_server = "stun.l.google.com";
    uint16_t stun_port_num = 19302;
    int packet_count = 50; // Analiz için toplanacak port sayısı

    // Önce özel modları kontrol et
    if (argc > 1) {
        std::string mode = argv[1];
        if (mode == "help" || mode == "-h" || mode == "--help") {
            std::cout << "\n🔧 USAGE MODES:" << std::endl;
            std::cout << "  ./randomness_breaker [stun_server] [port] [packet_count]" << std::endl;
            std::cout << "    Default analysis mode with specified parameters" << std::endl;
            std::cout << "\n  ./randomness_breaker master" << std::endl;
            std::cout << "    Birthday-paradox master NAT traversal strategy" << std::endl;
            std::cout << "\n  ./randomness_breaker entropy" << std::endl;
            std::cout << "    Entropy heatmap analysis only" << std::endl;
            std::cout << "\n  ./randomness_breaker server [port]" << std::endl;
            std::cout << "    P2P server mode for testing connections" << std::endl;
            std::cout << "\n  ./randomness_breaker target <port_number>" << std::endl;
            std::cout << "    Target specific port attack mode" << std::endl;
            std::cout << "\n  ./randomness_breaker symmetric" << std::endl;
            std::cout << "    Test symmetric NAT behavior (same source, different destinations)" << std::endl;
            std::cout << "\n📚 EXAMPLES:" << std::endl;
            std::cout << "  ./randomness_breaker master" << std::endl;
            std::cout << "  ./randomness_breaker entropy" << std::endl;
            std::cout << "  ./randomness_breaker symmetric" << std::endl;
            std::cout << "  ./randomness_breaker target 20000" << std::endl;
            std::cout << "  ./randomness_breaker server 8888" << std::endl;
            std::cout << "  ./randomness_breaker stun.l.google.com 19302 100" << std::endl;
            return 0;
        }
        else if (mode == "master" || mode == "birthday") {
            std::cout << "\n🎯 BIRTHDAY-PARADOX NAT TRAVERSAL MODE" << std::endl;
            std::cout << "Using advanced mathematical approach for NAT traversal..." << std::endl;
            initialize_analyzer(stun_server, stun_port_num);
            execute_master_nat_traversal_strategy();
            cleanup_analyzer();
            return 0;
        }
        else if (mode == "entropy") {
            std::cout << "\n🔥 ENTROPY HEATMAP ANALYSIS MODE" << std::endl;
            initialize_analyzer(stun_server, stun_port_num);
            auto targets = select_multi_stun_targets(3);
            auto heatmap = measure_phase_multi_stun(targets, 256);
            
            if (!heatmap.bins.empty()) {
                std::cout << "\n📊 ENTROPY ANALYSIS COMPLETE:" << std::endl;
                std::cout << "Effective port space reduced from full range to " 
                          << heatmap.n_effective << " ports" << std::endl;
                std::cout << "Concentration ratio: " << std::fixed << std::setprecision(2) 
                          << (heatmap.concentration_ratio * 100) << "%" << std::endl;
                
                auto plan = calculate_birthday_paradox_plan(heatmap.n_effective, 0.99);
                std::cout << "\n💡 For 99% success probability, you need ~" 
                          << plan.m_optimal << " simultaneous attempts" << std::endl;
            }
            
            cleanup_analyzer();
            return 0;
        }
        else if (mode == "server") {
            uint16_t server_port = 8888;
            if (argc > 2) {
                server_port = static_cast<uint16_t>(std::stoi(argv[2]));
            }
            
            std::cout << "\n🚀 Starting P2P Server Mode..." << std::endl;
            run_p2p_server(server_port);
            return 0;
        }
        else if (mode == "symmetric") {
            std::cout << "\n🔍 SYMMETRIC NAT BEHAVIOR TEST" << std::endl;
            std::cout << "Testing same source port to different destinations..." << std::endl;
            
            initialize_analyzer(stun_server, stun_port_num);
            
            // Test: Aynı source port, farklı destination'lar
            uint16_t test_source_port = 10012;
            
            std::vector<std::pair<std::string, std::string>> test_destinations = {
                {"74.125.250.129", "Google STUN"},
                {"74.125.250.129", "Google STUN (port 3478)"},  // Farklı port
                {"74.125.250.129", "Google STUN (port 5349)"},  // Farklı port
                {"142.250.191.127", "Google STUN 2"}            // Farklı Google IP
            };
            
            std::cout << "🎯 Testing source port " << test_source_port << " to different destinations:" << std::endl;
            
            for (const auto& dest : test_destinations) {
                uint16_t port = (dest.second.find("3478") != std::string::npos) ? 3478 :
                               (dest.second.find("5349") != std::string::npos) ? 5349 : 19302;
                
                uint16_t result = execute_single_request_to_destination(test_source_port, dest.first, port);
                std::cout << "   📊 " << test_source_port << " → " << dest.first << ":" << port 
                          << " (" << dest.second << "): " << result << std::endl;
            }
            
            std::cout << "\n🔍 SYMMETRIC NAT ANALYSIS:" << std::endl;
            std::cout << "If all results are the same → Full Cone NAT" << std::endl;
            std::cout << "If results differ → Symmetric NAT" << std::endl;
            std::cout << "\n💡 FOR SYMMETRIC NAT P2P:" << std::endl;
            std::cout << "1. Both peers must coordinate timing" << std::endl;
            std::cout << "2. Use birthday-paradox with predicted port ranges" << std::endl;
            std::cout << "3. Simultaneous hole punching required" << std::endl;
            std::cout << "4. Entropy analysis reduces search space" << std::endl;
            
            cleanup_analyzer();
            return 0;
        }
        else if (mode == "target") {
            if (argc < 3) {
                std::cout << "❌ Usage: ./randomness_breaker target <port_number>" << std::endl;
                std::cout << "Example: ./randomness_breaker target 20000" << std::endl;
                return 1;
            }
            
            uint16_t target_port = static_cast<uint16_t>(std::stoi(argv[2]));
            std::cout << "\n🎯 TARGET PORT ATTACK MODE" << std::endl;
            std::cout << "Target Port: " << target_port << std::endl;
            
            initialize_analyzer(stun_server, stun_port_num);
            
            // Önce analiz yap
            if (!execute_high_performance_burst(100)) {
                std::cout << "❌ Failed to collect initial measurements" << std::endl;
                cleanup_analyzer();
                return 1;
            }
            
            // Kapsamlı analiz
            run_comprehensive_analysis();
            
            // Hedef port saldırısı
            bool success = execute_targeted_port_attack(target_port);
            
            if (success) {
                std::cout << "\n✅ SUCCESS! Port " << target_port << " successfully targeted!" << std::endl;
                std::cout << "🎉 NAT traversal achieved using predictive algorithms!" << std::endl;
            } else {
                std::cout << "\n❌ Target port attack failed. Trying fallback strategies..." << std::endl;
                
                // Birthday-paradox ile deneme
                auto heatmap = measure_phase_multi_stun(select_multi_stun_targets(3), 64);
                if (!heatmap.bins.empty()) {
                    auto plan = calculate_birthday_paradox_plan(heatmap.n_effective, 0.95);
                    
                    PeerInfo demo_peer;
                    demo_peer.public_ip = "8.8.8.8";
                    demo_peer.public_port = target_port;
                    demo_peer.nat_type = "symmetric";
                    demo_peer.last_seen = get_timestamp_us();
                    
                    bool bp_success = execute_simultaneous_punch_with_birthday_paradox(plan, heatmap, demo_peer);
                    
                    if (bp_success) {
                        std::cout << "✅ Birthday-paradox approach succeeded!" << std::endl;
                    } else {
                        std::cout << "❌ All approaches failed for port " << target_port << std::endl;
                    }
                }
            }
            
            cleanup_analyzer();
            return 0;
        }
    }

    // Normal komut satırı argümanlarını işle
    if (argc > 1 && std::string(argv[1]) != "master" && std::string(argv[1]) != "entropy" && 
        std::string(argv[1]) != "server" && std::string(argv[1]) != "target") {
        stun_server = argv[1];
    }
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
    
    // Port tahminleri yap
    std::cout << "\n" << std::string(60, '=') << std::endl;
    auto predictions = predict_next_ports(10);
    
    // NAT tipi tespiti
    std::cout << "\n" << std::string(60, '=') << std::endl;
    bool nat_detected = execute_nat_type_detection();
    
    if (nat_detected && !predictions.empty()) {
        std::cout << "\n🎯 NAT TRAVERSAL DEMONSTRATION:" << std::endl;
        std::cout << "=" << std::string(40, '=') << std::endl;
        
        // Örnek peer bilgisi (demo için)
        PeerInfo demo_peer;
        demo_peer.public_ip = "8.8.8.8"; // Demo IP
        demo_peer.public_port = 12345;   // Demo port
        demo_peer.private_ip = "192.168.1.100";
        demo_peer.private_port = 54321;
        demo_peer.nat_type = "symmetric";
        demo_peer.last_seen = get_timestamp_us();
        
        std::cout << "📊 Demo P2P connection attempt with predicted ports..." << std::endl;
        
        // Hole punching denemesi (demo)
        HolePunchResult punch_result = execute_hole_punching(demo_peer);
        
        if (punch_result.success) {
            std::cout << "✅ Demo hole punching successful!" << std::endl;
        } else {
            std::cout << "ℹ️  Demo hole punching (expected to fail - no real peer)" << std::endl;
        }
        
        // P2P server modu seçeneği
        std::cout << "\n🖥️  P2P SERVER MODE:" << std::endl;
        std::cout << "To test P2P connections, you can run:" << std::endl;
        std::cout << "   ./randomness_breaker server <port>" << std::endl;
        std::cout << "Example: ./randomness_breaker server 8888" << std::endl;
    }

    // Kaynakları temizle
    cleanup_analyzer();
    return 0;
}
