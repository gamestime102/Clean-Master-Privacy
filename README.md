# 🛡️ Clean Master Privacy

Ultimate Security, Optimization & Privacy Suite

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![GTK4](https://img.shields.io/badge/GTK-4.0-blue.svg)](https://www.gtk.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## ✨ ÖZELLİKLER

### 🦠 Gelişmiş Antivirus
- Gerçek zamanlı dosya sistemi izleme
- Çoklu tarama motoru (İmza + Buluşsal + Davranışsal)
- Bulut tabanlı tehdit zekası
- Otomatik karantina ve geri yükleme
- Bellek ve önyükleme taraması

### ⚡ Sistem Optimizasyonu
- Akıllı çöp dosya temizleyici (10+ kategori)
- Başlangıç programı yöneticisi
- Disk ve RAM optimizasyonu
- Sistem sağlığı izleme ve öneriler
- Otomatik bakım

### 🔒 Güvenlik ve Gizlilik
- Kapsamlı güvenlik denetimi (14+ kontrol)
- Gizlilik sorunları tarayıcı
- Anonimleştirme araçları
- Ağ güvenliği kontrolü
- Şifre ve hesap güvenliği

### 💻 Donanım Sağlığı
- Gerçek zamanlı donanım izleme
- Sıcaklık, fan ve voltaj takibi
- Pil sağlığı analizi
- Sürücü güncelleme kontrolü
- Performans önerileri

### 🎨 Modern Arayüz
- Koyu/Açık tema desteği
- Çoklu dil desteği (Türkçe, İngilizce, Almanca, Fransızca, İspanyolca)
- Gerçek zamanlı istatistikler
- Bildirim sistemi
- Responsive tasarım

### 📊 Sistem İzleme
- Canlı CPU, RAM, Disk kullanımı
- Sıcaklık ve fan hızı takibi
- İşlem ve servis yönetimi
- Ağ bağlantıları izleme
- Günlük kayıtları

### 🛠️ Ek Araçlar
- Karantina yöneticisi
- Otomatik yedekleme
- Sistem geri yükleme
- Güvenlik duvarı yapılandırması
- VPN ve proxy desteği

## 🚀 Hızlı Başlangıç

### Yöntem 1: Otomatik Kurulum (Önerilen)

```bash
# Script'i indirin
wget https://raw.githubusercontent.com/gamestime102/Clean-Master-Privacy/main/install.sh

# Çalıştırma izni verin
chmod +x install.sh

# Kurulumu başlatın
./install.sh --system  # Sistem geneli (sudo gerektirir)
# VEYA
./install.sh --user    # Sadece mevcut kullanıcı
```

### Yöntem 2: Manuel Kurulum

#### Gereksinimler

- Rust 1.75+
- GTK4 geliştirme kütüphaneleri
- Libadwaita

#### Debian/Ubuntu

```bash
# Bağımlılıkları yükleyin
sudo apt-get update
sudo apt-get install -y \
    libgtk-4-dev \
    libadwaita-1-dev \
    libssl-dev \
    pkg-config \
    desktop-file-utils

# Repoyu klonlayın
git clone https://github.com/gamestime102/Clean-Master-Privacy.git
cd Clean-Master-Privacy

# Derleyin ve yükleyin
cargo build --release
sudo cp target/release/clean-master-privacy /usr/local/bin/
```

#### Fedora

```bash
sudo dnf install gtk4-devel libadwaita-devel openssl-devel pkg-config
```

#### Arch Linux

```bash
sudo pacman -S gtk4 libadwaita openssl pkgconf
```

## 🛠️ Derleme

```bash
# Debug modunda derleme
cargo build

# Release modunda derleme
cargo build --release

# Debian paketi oluşturma
cargo install cargo-deb
cargo deb
```

## 🧪 Test

```bash
# Tüm testleri çalıştır
cargo test

# Belirli bir test çalıştır
cargo test test_adı
```

## 📋 Kullanım

```bash
# GUI'yi başlat
clean-master-privacy

# Hızlı tarama başlat
clean-master-privacy --quick-scan

# Tam tarama başlat
clean-master-privacy --full-scan

# Sistem optimizasyonu
clean-master-privacy --optimize

# Gizlilik denetimi
clean-master-privacy --privacy-audit

# Versiyon bilgisi
clean-master-privacy --version

# Yardım
clean-master-privacy --help
```

## 🏗️ Proje Yapısı

```
Clean-Master-Privacy/
├── src/
│   ├── main.rs      # Uygulama giriş noktası
│   ├── core.rs      # Çekirdek motor ve işlemler
│   ├── ui.rs        # GTK4 kullanıcı arayüzü
│   └── lib.rs       # Kütüphane modülü
├── assets/          # İkonlar ve desktop dosyaları
├── .github/         # GitHub Actions workflow'ları
├── Cargo.toml       # Rust bağımlılıkları
├── build.sh         # Derleme scripti
├── install.sh       # Kurulum scripti
└── README.md        # Bu dosya
```

## 🤝 Katkıda Bulunma

1. Bu repoyu fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- [GTK4](https://www.gtk.org) - Modern GUI toolkit
- [Libadwaita](https://gitlab.gnome.org/GNOME/libadwaita) - GNOME tasarım bileşenleri
- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Sistem bilgisi kütüphanesi
- [notify](https://github.com/notify-rs/notify) - Dosya sistemi izleme
- [rayon](https://github.com/rayon-rs/rayon) - Veri paralelliği

## 📞 İletişim

- GitHub Issues: [https://github.com/gamestime102/Clean-Master-Privacy/issues](https://github.com/gamestime102/Clean-Master-Privacy/issues)
- Discussions: [https://github.com/gamestime102/Clean-Master-Privacy/discussions](https://github.com/gamestime102/Clean-Master-Privacy/discussions)

---

⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!
