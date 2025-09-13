# 🎯 Advanced NAT Traversal with Birthday-Paradox

## 🚀 Overview

Bu araç, simetrik NAT'ları geçerek P2P güvenli iletişimi sağlamak için gelişmiş matematiksel yaklaşımlar kullanır. **Birthday-Paradox teorisi**, **entropi analizi** ve **PRNG seed çıkarımı** ile NAT'ın port atama rastgeleliğini kırarak etkili hole punching gerçekleştirir.

## 🧮 Matematiksel Temel

### Birthday-Paradox Formülü
İki taraf da `m` adet deneme portu ürettiğinde, port uzayı `N` içinde en az bir çakışma olasılığı:

```
P(çakışma) ≈ 1 - e^(-m²/N)
```

%99 başarı için gerekli atış sayısı:
```
m ≈ 2.146 × √N
```

### Senaryolar
- **Mobil ağ** (N ≈ 800): ~61 atış
- **Ev ağı** (N ≈ 5,000): ~152 atış  
- **Kurumsal** (N ≈ 30,000): ~372 atış

## 🔧 Kullanım

### Temel Modlar

```bash
# Birthday-Paradox master strateji
./randomness_breaker master

# Sadece entropi analizi
./randomness_breaker entropy

# P2P server modu
./randomness_breaker server 8888

# Geleneksel analiz
./randomness_breaker stun.l.google.com 19302 100

# Yardım
./randomness_breaker help
```

### Master Strateji Aşamaları

1. **S0: Ölçüm** → Çoklu-STUN paralel burst + saat damgalama
2. **S1: PRNG Seed Çıkarımı** → Keskin tahmin vs entropi haritası  
3. **S2/S3: Pencere Daraltma** → N_keen veya N_eff hesaplama
4. **S4: Simultaneous Punch** → Birthday-paradox ile çakışma
5. **S5: Fallback** → Observer-assisted veya mini-TURN relay

## 🔬 Teknik Özellikler

### Analiz Algoritmaları
- ✅ Shannon Entropi Analizi
- ✅ Markov Chain Geçiş Matrisi  
- ✅ Berlekamp-Massey Linear Complexity
- ✅ Bit-Plane Entropi Analizi
- ✅ Chi-Square Uniformity Test
- ✅ Spektral Analiz (DFT)
- ✅ PRNG Seed Brute-Force (LCG, MT19937)

### NAT Traversal Teknikleri
- 🎯 Birthday-Paradox Port Collision
- 🔥 Entropy Heatmap Daraltma
- ⏰ Global Clock Synchronization
- 🥷 Stealth Burst (IDS/Firewall Dostu)
- 🔄 Phase Lock & Jitter
- 👂 Promiscuous Collision Detection

### Güvenlik Özellikleri
- Aşamalı burst boyutları (stealth)
- Mikrosaniye-seviye jitter
- Inter-batch delay randomization
- Port reuse prevention
- Erken collision detection

## 📊 Çıktı Örnekleri

### Entropi Haritası
```
🔥 ENTROPY HEATMAP RESULTS:
Hot bins: 25/128
Effective port space: 3200 (concentration: 78.43%)
Top hot bins:
   🔥 18000-18250: 45 hits (18.2%)
   🔥 19500-19750: 38 hits (15.4%)
```

### Birthday-Paradox Hesaplama
```
🎂 BIRTHDAY-PARADOX CALCULATION:
Port space size (N): 3200
Target probability: 0.990
📊 Optimal shot count (m): 152
📊 Actual success probability: 0.9918
📊 Stealth batches: 60 → 51 → 41 = 152
```

## 🛡️ Güvenlik Notları

Bu araç **eğitim ve araştırma** amaçlıdır. Kullanım:
- Kendi ağınızda test
- Güvenlik araştırması  
- NAT implementasyonu analizi

**Yasal uyarı**: Yetkisiz ağlarda kullanmayın.

## 🔗 P2P Bağlantı Testi

```bash
# Terminal 1: Server
./randomness_breaker server 8888

# Terminal 2: Master strateji
./randomness_breaker master
```

## 📈 Performans

- **Burst Rate**: ~170k paket/saniye
- **Memory Usage**: <50MB
- **Latency**: Sub-millisecond timing
- **Success Rate**: %99+ (optimal conditions)

## 🧪 Gelişmiş Özellikler

### Multi-STUN Ölçüm
- Paralel hedef testing
- RTT correlation analysis
- Cross-validation

### PRNG Model Detection  
- Linear Congruential Generator (LCG)
- Mersenne Twister (MT19937)
- XORShift variants
- Time-based correlation

### Adaptive Algorithms
- Dynamic window adjustment
- Real-time entropy recalculation  
- Feedback-based optimization
