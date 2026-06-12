# GhostWire CTI v6.1 — Windows Docker Quraşdırma

## Tələblər

- Windows 10/11 (64-bit)
- Docker Desktop 4.x+ → https://www.docker.com/products/docker-desktop
- WSL2 (Docker Desktop qurarkən avtomatik aktivləşir)
- RAM: minimum 4 GB (8 GB tövsiyə)
- Disk: ~5 GB (image + Ollama modeli)

---

## 1. Addım — Docker Desktop quraşdır

1. https://www.docker.com/products/docker-desktop — Download
2. İnstaller-i çalışdır, "Use WSL2" seçimini aktiv saxla
3. Restart et
4. Docker Desktop-u aç — system tray-da balina ikonu görünməlidir

**Yoxla:**
```powershell
docker --version
docker compose version
```

---

## 2. Addım — `.env` faylını hazırla

Repo qovluğunda `.env.example` faylı var. Onu kopyala:

```powershell
copy .env.example .env
```

Sonra `.env` faylını notepad/VS Code ilə aç və API key-ləri doldur:

```env
VIRUSTOTAL_API_KEY=buraya_vt_key
ABUSEIPDB_API_KEY=buraya_abuse_key
URLHAUS_API_KEY=buraya_urlhaus_key

# Bunlar opsionaldır — boş qoya bilərsiniz
SHODAN_API_KEY=
GREYNOISE_API_KEY=
HYBRID_ANALYSIS_API_KEY=
```

---

## 3. Addım — Image build et

PowerShell və ya CMD ilə repo qovluğuna gir:

```powershell
cd C:\path\to\GhostWire_CTI_v6
docker compose build
```

İlk dəfə ~5-10 dəq çəkir (Playwright Chromium yüklənir).

---

## 4. Addım — Konteynerləri başlat

```powershell
docker compose up -d
```

İki konteyner başlayır:
- `ghostwire` — Streamlit app
- `ghostwire-ollama` — Local AI

---

## 5. Addım — Ollama modelini yüklə (bir dəfəlik)

```powershell
docker compose down
# Volume adını tap
docker volume ls | findstr ollama
#silmək üçün 
docker volume rm ollama_name
# yeniden yuklemek 
docker exec ghostwire-ollama ollama pull phi3:mini
```

~2.3 GB yüklənir. Bir dəfə lazımdır — volume-da saxlanılır.

---

## 6. Addım — Aç

Brauzer: **http://localhost:8501**

---

## Gündəlik istifadə

```powershell
# Başlat
docker compose up -d

# Dayandır
docker compose down

# Log-lara bax
docker compose logs -f

# Status
docker compose ps
```

---

## Troubleshooting

### Port 8501 məşğuldur
```powershell
# Hansı proses işlədiyini tap
netstat -ano | findstr :8501
# docker-compose.yml-də portu dəyiş: "8502:8501"
```

### Ollama modeli yüklənmir
Ollama-nın internet bağlantısı yoxdur (təhlükəsizlik üçün).  
Modeli host-da yüklə, sonra container-ə köçür:
```powershell
# Docker-in xaricindən Ollama yüklə (https://ollama.com)
ollama pull phi3:mini

# Modeli container volume-una kopyala
docker cp %USERPROFILE%\.ollama\models ghostwire-ollama:/root/.ollama/
```

### "ghostwire-ollama" health check fail
Ollama başlamaq üçün vaxt lazımdır. 1-2 dəq gözlə:
```powershell
docker logs ghostwire-ollama --tail=20
```

### Build xətası — "no space left"
Docker Desktop → Settings → Resources → Disk image size → artır

---

## Faydalı komandalar

```powershell
# Audit log-ları oxu
docker exec ghostwire cat /app/logs/audit.jsonl

# Container-ə daxil ol
docker exec -it ghostwire bash

# Image-i sil, yenidən build et
docker compose down
docker rmi ghostwire-cti:6.1
docker compose build --no-cache
docker compose up -d
```

# Kod dəyişikliyi (app.py, backend/, frontend/ və s.)
```powershell 
docker compose build
docker compose up -d
```

# Yalnız restart lazımdırsa
```powershell 
docker compose restart
```
# requirements.txt dəyişibsə (yeni paket əlavə etmisən)
```powershell
docker compose build --no-cache
docker compose up -d
```
# docker-compose.yml dəyişibsə
```powershell 
docker compose down
docker compose up -d
```
# artiq cache zibil files silmek :
```powershell 
docker system prune -f
```