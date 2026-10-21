"""
analiz.py - WAN Trafik Dinleme, DPI ve Zafiyet Tespit Motoru (v4)
Gereksinim: pip install scapy
Windows icin Npcap surucusu kurulu olmalidir. Yonetici yetkisiyle calistirin.
"""

import csv
import os
import re
import struct
from datetime import datetime
from scapy.all import sniff, conf, IP, TCP, UDP, Raw

# ─────────────────────────────────────────
# YAPILANDIRMA
# ─────────────────────────────────────────

IFACE_INDEX   = 2
CSV_DOSYASI   = "kapsamli_analiz_raporu.csv"
HTTPS_PORTLAR = {443, 8443, 465, 993, 995, 587}

# ─────────────────────────────────────────
# TLS / SSL TANIM TABLOLARI
# ─────────────────────────────────────────

TLS_SURUM_ADLARI = {
    (0x03, 0x04): "TLS 1.3",
    (0x03, 0x03): "TLS 1.2",
    (0x03, 0x02): "TLS 1.1",
    (0x03, 0x01): "TLS 1.0",
    (0x03, 0x00): "SSL 3.0",
    (0x02, 0x00): "SSL 2.0",
}

TLS_ESKI_SURUMLER = {
    "SSL 2.0": (
        "Kritik Risk",
        "[SSL 2.0 TESPIT] SSL 2.0 1996da yasaklandi (RFC 6176). "
        "DROWN saldirisi (CVE-2016-0800) ile sifreleme tamamen kiriliyor. "
        "Sunucudan SSL 2.0 destegi DERHAL kaldirilmali."
    ),
    "SSL 3.0": (
        "Kritik Risk",
        "[SSL 3.0 TESPIT] SSL 3.0 POODLE saldirisi (CVE-2014-3566) ile kirildi. "
        "RFC 7568 ile kullanimi yasaklandi. TLS 1.2 veya TLS 1.3 kullanilmali."
    ),
    "TLS 1.0": (
        "Yuksek Risk",
        "[TLS 1.0 TESPIT] TLS 1.0, BEAST (CVE-2011-3389) ve POODLE saldirilarina karsi "
        "savunmasiz. PCI-DSS 3.2+ TLS 1.0 kullanimini yasaklamaktadir. "
        "TLS 1.2 veya TLS 1.3e gecilmeli."
    ),
    "TLS 1.1": (
        "Yuksek Risk",
        "[TLS 1.1 TESPIT] TLS 1.1, RFC 8996 ile Mart 2021de kullanim disi birakildi. "
        "Zayif MAC algoritmalari (MD5/SHA-1) kullaniyor. TLS 1.2 veya TLS 1.3 zorunlu."
    ),
    "TLS 1.2": (
        "Bilgi",
        "[TLS 1.2] Kabul edilebilir surum. Ancak modern sistemlerde "
        "TLS 1.3 tercih edilmeli. Zayif cipher suite kullaniliyorsa risk artabilir."
    ),
    "TLS 1.3": (
        "Bilgi",
        "[TLS 1.3] Guncel ve guvenli TLS surumu. Mukemmel ileri gizlilik (PFS) "
        "sagliyor. Bilinen kritik acik yok."
    ),
}

# ─────────────────────────────────────────
# BANNER GRABBING - ZAFIYETLI SUNUCU SURUMLERI
# ─────────────────────────────────────────

ZAFIYETLI_SURUMLER = [
    ("Apache/2.2",        "Apache 2.2 destegi 2017de sona erdi. CVE-2017-7679 dahil 30+ kritik CVE. Hemen Apache 2.4e geciniz."),
    ("Apache/2.0",        "Apache 2.0 cok eski (2002). Yuzlerce bilinen CVE mevcut. Acil guncelleme gerekli."),
    ("Apache/1.3",        "Apache 1.3 desteklenmiyor (EOL). Uretim ortaminda kullanimi kritik risk olusturur."),
    ("nginx/1.0",         "nginx 1.0 desteklenmemektedir. CVE-2013-2070 gibi buffer overflow aciklari icerir."),
    ("nginx/1.2",         "nginx 1.2 EOL. Guvenlik yamalari uygulanmamaktadir."),
    ("nginx/1.4",         "nginx 1.4 EOL. SPDY implementasyonunda kritik aciklar mevcuttur."),
    ("nginx/1.6",         "nginx 1.6 desteklenmiyor. En az nginx 1.24 (stable) kullanilmalidir."),
    ("Microsoft-IIS/6.0", "IIS 6.0 (Windows Server 2003) EOS. CVE-2017-7269 ile uzaktan kod calistirmaya acik!"),
    ("Microsoft-IIS/7.0", "IIS 7.0 destegi sona erdi. Lokal ayricalik yukseltme aciklari mevcut."),
    ("Microsoft-IIS/7.5", "IIS 7.5 (Windows 7/2008 R2) EOL. Kritik guvenlik yamalari uygulanmiyor."),
    ("PHP/4.",            "PHP 4 tamamen desteksiz. Yuzlerce RCE acigi var. Derhal kaldirin."),
    ("PHP/5.",            "PHP 5.x destegi 2018de sona erdi. CVE-2019-11043 RCE acigi icerir. PHP 8.xe geciniz."),
    ("PHP/7.0",           "PHP 7.0 EOL (2019). Guncel guvenlik yamalarindan yoksun. PHP 8.2+ onerilir."),
    ("PHP/7.1",           "PHP 7.1 EOL (2019). Kritik type juggling aciklari mevcuttur."),
    ("PHP/7.2",           "PHP 7.2 EOL (2020). Guvenlik guncellemesi almiyor."),
    ("OpenSSL/1.0",       "OpenSSL 1.0.x EOL. Heartbleed (CVE-2014-0160) dahil kritik TLS aciklari icerir."),
    ("OpenSSL/1.1.0",     "OpenSSL 1.1.0 destegi sona erdi. OpenSSL 3.xe gecilmesi onerilir."),
]

# ─────────────────────────────────────────
# EKSIK HTTP GUVENLIK BASLIKLARI
# ─────────────────────────────────────────

GUVENLIK_BASLIKLARI = {
    "Content-Security-Policy": (
        "Orta Risk",
        "CSP basligi eksik. Saldirgan sayfaya zarali script enjekte ederek XSS saldirisi gerceklestirebilir. Kullanici oturum cerezleri calinabilir."
    ),
    "X-Frame-Options": (
        "Orta Risk",
        "X-Frame-Options eksik. Site iframe icine alinarak Clickjacking saldirisina karsi savunmasiz. Kullanici farkinda olmadan zarali tiklamalara yonlendirilebilir."
    ),
    "Strict-Transport-Security": (
        "Orta Risk",
        "HSTS eksik. Tarayici HTTPS yerine HTTP ye dusurulebilir (SSL Stripping). MITM saldirisıyla trafik sifreli olmadan ele gecirilir."
    ),
    "X-Content-Type-Options": (
        "Dusuk Risk",
        "X-Content-Type-Options nosniff eksik. Tarayici MIME turunu gormezden gelerek zarali icerigi calistirabililr (MIME Sniffing saldirisi)."
    ),
    "Referrer-Policy": (
        "Dusuk Risk",
        "Referrer-Policy eksik. Kullanici baska siteye gectiginde hassas URL parametreleri (oturum ID, token) Referer basligi ile sizdirilabilir."
    ),
    "Permissions-Policy": (
        "Dusuk Risk",
        "Permissions-Policy eksik. Kamera, mikrofon, konum gibi tarayici API lerine yetkisiz erisim engellenemiyor."
    ),
    "Cache-Control": (
        "Dusuk Risk",
        "Cache-Control basligi eksik. Hassas sayfalar tarayici veya proxy onbelleklerinde saklanabilir. "
        "no-store ve no-cache direktifleri kullanilmali."
    ),
}

# ─────────────────────────────────────────
# SQL INJECTION / XSS TETIKLEYICI KALIPLAR
# ─────────────────────────────────────────

SQL_INJECTION_KALIPLARI = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"((\%27)|(\'))union",
    r"select.+from",
    r"insert.+into",
    r"drop\s+table",
    r"(\bOR\b.+\b1\b.+=.+\b1\b)",
    r"(\bAND\b.+\b1\b.+=.+\b1\b)",
    r"sleep\s*\(\s*\d+\s*\)",
    r"benchmark\s*\(",
    r"waitfor\s+delay",
    r"(\bEXEC\b|\bEXECUTE\b).+(\bxp_\w+\b)",
]

XSS_KALIPLARI = [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"on\w+\s*=\s*['\"]",
    r"<\s*img[^>]+onerror",
    r"<\s*svg[^>]+onload",
    r"document\s*\.\s*cookie",
    r"eval\s*\(",
    r"alert\s*\(",
    r"<\s*iframe[^>]*>",
    r"expression\s*\(",
]

PATH_TRAVERSAL_KALIPLARI = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows\\",
    r"boot\.ini",
    r"win\.ini",
]

HASSAS_BILGI_KALIPLARI = {
    r"\b(?:\d[ -]?){13,16}\b":                                          ("Kredi Karti Numarasi", "Yuksek Risk"),
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b":           ("E-posta Adresi",       "Dusuk Risk"),
    r"password\s*=\s*[^\s&]+":                                          ("Sifre Parametresi",    "Kritik Risk"),
    r"passwd\s*=\s*[^\s&]+":                                            ("Sifre Parametresi",    "Kritik Risk"),
    r"api[_-]?key\s*=\s*[^\s&]+":                                       ("API Anahtari",         "Kritik Risk"),
    r"token\s*=\s*[^\s&]{8,}":                                          ("Token Sizintisi",      "Yuksek Risk"),
    r"secret\s*=\s*[^\s&]+":                                            ("Gizli Parametre",      "Kritik Risk"),
    r"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*":                ("Bearer Token",         "Yuksek Risk"),
    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----":                          ("Ozel Anahtar (PEM)",   "Kritik Risk"),
}

# ─────────────────────────────────────────
# PORT / PROTOKOL TABLOLARI
# ─────────────────────────────────────────

PORT_PROTOKOL = {
    80:    "HTTP",
    443:   "HTTPS",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    123:   "NTP",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    25:    "SMTP",
    465:   "SMTPS",
    587:   "SMTP-Sub",
    110:   "POP3",
    995:   "POP3S",
    143:   "IMAP",
    993:   "IMAPS",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    1433:  "MSSQL",
    27017: "MongoDB",
    6379:  "Redis",
    137:   "NetBIOS",
    138:   "NetBIOS",
    139:   "NetBIOS",
    445:   "SMB",
    4444:  "Metasploit-Shell",
    31337: "Back-Orifice",
}

TEHLIKELI_PORTLAR = {
    23:    ("Yuksek Risk", "Telnet sifreli degil. Kullanici adi/parola acik metin gonderilir. SSH ile degistirilmeli."),
    4444:  ("Kritik Risk", "Port 4444 Metasploit varsayilan reverse shell portudur. Zararli yazilim baglantisi olabilir!"),
    31337: ("Kritik Risk", "Port 31337 Back Orifice RAT tarafindan kullanilir. Sistem ele gecirilmis olabilir!"),
    445:   ("Yuksek Risk", "SMB acik. EternalBlue (CVE-2017-0144) WannaCry/NotPetya saldirisi riski."),
    3389:  ("Yuksek Risk", "RDP acik. Brute-force ve BlueKeep (CVE-2019-0708) acigina karsi savunmasiz."),
    5900:  ("Yuksek Risk", "VNC acik. Zayif parola/sifreli baglanti riski yuksek."),
    27017: ("Yuksek Risk", "MongoDB acik. Kimlik dogrulama yoksa tum veritabani okuma/yazma riski."),
    6379:  ("Yuksek Risk", "Redis acik. Kimlik dogrulama yoksa uzaktan komut calistirma (RCE) mumkun."),
    21:    ("Orta Risk",   "FTP sifreli degil. Kimlik bilgileri acik metin iletilir. SFTP kullanin."),
}

# Ayni TLS IP cifti tekrar loglanmasin
_tls_goruldu = set()

# ─────────────────────────────────────────
# YARDIMCI: PORT SEC
# ─────────────────────────────────────────

def bilinen_port_sec(dport, sport):
    """
    Gelen ve giden portlardan anlamli olani sec.
    1. dport bilinen portsa -> dport  (istemci sunucuya gidiyor)
    2. sport bilinen portsa -> sport  (sunucu istemciye cevap veriyor)
    3. Ikisi de bilinmiyorsa -> kucuk olan (servis portu genellikle kucuktur)
    """
    if dport in PORT_PROTOKOL:
        return dport
    if sport in PORT_PROTOKOL:
        return sport
    if dport and sport:
        return min(dport, sport)
    return dport or sport

# ─────────────────────────────────────────
# PORT SINIFLANDIRMA
# ─────────────────────────────────────────

def port_siniflandir(port):
    if port is None:
        return "Bilinmiyor", "Bilgi", "Port bilgisi alinamadi."
    if port in PORT_PROTOKOL:
        protokol = PORT_PROTOKOL[port]
        if port in TEHLIKELI_PORTLAR:
            risk, aciklama = TEHLIKELI_PORTLAR[port]
            return protokol, risk, aciklama
        return protokol, "Bilgi", f"{protokol} protokolu normal trafigi gozlemlendi (Port {port})."
    if 49152 <= port <= 65535:
        return "Ephemeral Port", "Bilgi", (
            f"Port {port} dinamik/ephemeral araliginda (49152-65535). "
            "Isletim sistemi tarafindan gecici baglanti icin otomatik atanmis porttur. Normal davranis."
        )
    if 1024 <= port <= 49151:
        return f"Kayitli Port ({port})", "Bilgi", (
            f"Port {port} IANA kayitli araliginda (1024-49151). "
            "Standart bir uygulama tarafindan kullaniliyor olabilir."
        )
    if 1 <= port <= 1023:
        return f"Sistem Portu ({port})", "Orta Risk", (
            f"Port {port} ayricalikli sistem portu araliginda (1-1023). "
            "Bilinmeyen bir servis varsa incelenmeli."
        )
    return f"Port {port}", "Bilgi", f"Port {port} uzerinde trafik gozlemlendi."

# ─────────────────────────────────────────
# CSV
# ─────────────────────────────────────────

def csv_baslat():
    if not os.path.exists(CSV_DOSYASI):
        with open(CSV_DOSYASI, "w", newline="", encoding="utf-8-sig") as f:
            yazar = csv.writer(f, delimiter=";")
            yazar.writerow(["Zaman", "Kaynak IP", "Hedef IP", "Protokol", "Port",
                            "Zafiyet Turu", "Detay", "Risk Seviyesi"])
        print(f"[+] CSV olusturuldu: {CSV_DOSYASI}")

def kaydet(kaynak_ip, hedef_ip, protokol, port, zafiyet_turu, detay, risk):
    with open(CSV_DOSYASI, "a", newline="", encoding="utf-8-sig") as f:
        yazar = csv.writer(f, delimiter=";")
        yazar.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            kaynak_ip, hedef_ip, protokol,
            port if port is not None else "-",
            zafiyet_turu, detay, risk
        ])

# ─────────────────────────────────────────
# TLS / SSL PAKET ANALİZİ
# ─────────────────────────────────────────

def tls_surum_oku(raw_bytes):
    surumler = set()
    i = 0
    while i + 5 <= len(raw_bytes):
        content_type = raw_bytes[i]
        major        = raw_bytes[i + 1]
        minor        = raw_bytes[i + 2]
        try:
            length = struct.unpack("!H", raw_bytes[i + 3: i + 5])[0]
        except struct.error:
            break
        if (major, minor) in TLS_SURUM_ADLARI:
            surumler.add(TLS_SURUM_ADLARI[(major, minor)])
        if content_type == 0x16 and i + 10 <= len(raw_bytes):
            hs_major = raw_bytes[i + 9]
            hs_minor = raw_bytes[i + 10]
            if (hs_major, hs_minor) in TLS_SURUM_ADLARI:
                surumler.add(TLS_SURUM_ADLARI[(hs_major, hs_minor)])
        i += 5 + length
        if length == 0:
            break
    return surumler

def tls_analiz_et(kaynak_ip, hedef_ip, raw_bytes, port):
    cift = (kaynak_ip, hedef_ip)
    if cift in _tls_goruldu:
        return
    if not raw_bytes or raw_bytes[0] not in (0x14, 0x15, 0x16, 0x17):
        return
    surumler = tls_surum_oku(raw_bytes)
    if not surumler:
        return
    _tls_goruldu.add(cift)
    for surum_adi in surumler:
        risk, aciklama = TLS_ESKI_SURUMLER.get(
            surum_adi,
            ("Bilgi", f"[{surum_adi}] TLS surumu tespit edildi.")
        )
        print(f"  [TLS] {surum_adi} | {risk} | {kaynak_ip} -> {hedef_ip}")
        kaydet(kaynak_ip, hedef_ip, f"HTTPS (Port {port})", port,
               f"TLS/SSL Surum Analizi: {surum_adi}", aciklama, risk)

# ─────────────────────────────────────────
# HTTP DPI - TUM ZAFİYET KONTROLLERİ
# ─────────────────────────────────────────

def http_analiz_et(kaynak_ip, hedef_ip, raw_veri):
    try:
        metin = raw_veri.decode("utf-8", errors="ignore")
    except Exception:
        return

    if not (metin.startswith("HTTP/") or metin.startswith("GET ")
            or metin.startswith("POST ") or "Server:" in metin):
        return

    # Basliklari ayristir
    satirlar  = metin.split("\r\n")
    basliklar = {}
    for satir in satirlar[1:]:
        if ": " in satir:
            k, v = satir.split(": ", 1)
            basliklar[k.strip()] = v.strip()

    # ── KONTROL 1: Eksik Guvenlik Basliklari ─────────────────────────────
    # Yalnizca HTTP yaniti ise kontrol et
    if satirlar and satirlar[0].startswith("HTTP/"):
        for baslik, (risk, aciklama) in GUVENLIK_BASLIKLARI.items():
            if baslik not in basliklar:
                detay = f"[{baslik} EKSIK] {aciklama}"
                print(f"  [!] {risk} | {baslik} eksik -> {hedef_ip}")
                kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                       f"Eksik Baslik: {baslik}", detay, risk)

    # ── KONTROL 2: Banner Grabbing / Surum Sizintisi ──────────────────────
    sunucu = basliklar.get("Server", "")
    if sunucu:
        eslesti = False
        for eski, aciklama in ZAFIYETLI_SURUMLER:
            if eski.lower() in sunucu.lower():
                detay = f"[ZAFIYETLI SURUM] Tespit: '{sunucu}' -> {aciklama}"
                print(f"  [!!!] KRITIK | Banner Grabbing: {sunucu}")
                kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                       "Surum Sizintisi (Banner Grabbing)", detay, "Kritik Risk")
                eslesti = True
                break
        if not eslesti:
            detay = (
                f"[BILGI SIZINTISI] Sunucu surumu gorunur: '{sunucu}'. "
                "Saldirgan hedef almak icin kullanabilir. "
                "ServerTokens Prod veya server_tokens off ayari yapilmali."
            )
            print(f"  [~] Sunucu Bilgisi Acik: {sunucu}")
            kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                   "Sunucu Bilgisi Sizintisi", detay, "Dusuk Risk")

    # ── KONTROL 3: Guvensiz Cerez Yapilandirmasi ─────────────────────────
    set_cookie = basliklar.get("Set-Cookie", "")
    if set_cookie:
        eksik = []
        if "HttpOnly" not in set_cookie:
            eksik.append("HttpOnly (JS ile cerez okunabilir -> XSS riski artar)")
        if "Secure" not in set_cookie:
            eksik.append("Secure (Cerez HTTP uzerinden iletilebilir)")
        if "SameSite" not in set_cookie:
            eksik.append("SameSite (CSRF saldirisina karsi savunmasiz)")
        if eksik:
            detay = (
                f"[GUVENSSIZ CEREZ] Eksik bayraklar: {', '.join(eksik)}. "
                f"Cerez: '{set_cookie[:80]}'"
            )
            print(f"  [!] Guvenssiz Cerez -> {hedef_ip}")
            kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                   "Guvenssiz Cerez Yapilandirmasi", detay, "Yuksek Risk")

    # ── KONTROL 4: CORS Zafiyeti ─────────────────────────────────────────
    cors = basliklar.get("Access-Control-Allow-Origin", "")
    if cors == "*":
        detay = (
            "[CORS ZAFIYETI] Access-Control-Allow-Origin: * olarak ayarlanmis. "
            "Herhangi bir domain bu kaynaga AJAX istegi yapabilir. "
            "Hassas verilere yetkisiz erisim saglanabilir (Cross-Origin Data Theft)."
        )
        print(f"  [!] Yuksek Risk | CORS Wildcard -> {hedef_ip}")
        kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
               "CORS Zafiyeti (Wildcard Origin)", detay, "Yuksek Risk")

    cors_cred = basliklar.get("Access-Control-Allow-Credentials", "")
    if cors == "*" and cors_cred.lower() == "true":
        detay = (
            "[KRITIK CORS] Access-Control-Allow-Origin: * ile birlikte "
            "Access-Control-Allow-Credentials: true kullaniliyor. "
            "Kimlik dogrulamali istekler baska domain tarafindan okunabilir. Acil duzeltme gerekli!"
        )
        print(f"  [!!!] KRITIK | CORS + Credentials -> {hedef_ip}")
        kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
               "CORS + Credentials Zafiyeti", detay, "Kritik Risk")

    # ── KONTROL 5: Guvenli Olmayan HTTP Metotlari ─────────────────────────
    allow_metot = basliklar.get("Allow", "")
    if allow_metot:
        tehlikeli_metotlar = []
        for metot in ["TRACE", "TRACK", "DELETE", "PUT", "CONNECT"]:
            if metot in allow_metot.upper():
                tehlikeli_metotlar.append(metot)
        if tehlikeli_metotlar:
            detay = (
                f"[TEHLIKELI HTTP METOTLARI] Sunucu su metotlara izin veriyor: "
                f"{', '.join(tehlikeli_metotlar)}. "
                "TRACE/TRACK -> XST (Cross-Site Tracing) saldirisi. "
                "DELETE/PUT -> Yetkisiz dosya silme/yuklemesine izin verebilir."
            )
            print(f"  [!] Orta Risk | Tehlikeli HTTP Metot: {tehlikeli_metotlar}")
            kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                   "Tehlikeli HTTP Metotlari", detay, "Orta Risk")

    # ── KONTROL 6: Acik Yonlendirme (Open Redirect) ──────────────────────
    location = basliklar.get("Location", "")
    if location:
        # 3xx yonlendirmesi ve dis URL kontrolu
        if satirlar and satirlar[0].startswith("HTTP/"):
            durum = satirlar[0]
            if any(f" {k} " in durum for k in ["301", "302", "303", "307", "308"]):
                if location.startswith("http") and hedef_ip not in location:
                    detay = (
                        f"[ACIK YONLENDIRME] Sunucu dis bir URL ye yonlendiriyor: '{location}'. "
                        "Kimlik avı (phishing) saldirısında kullanilabilir. "
                        "Yonlendirmeler whitelist ile dogrulanmali."
                    )
                    print(f"  [!] Orta Risk | Acik Yonlendirme -> {location}")
                    kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                           "Acik Yonlendirme (Open Redirect)", detay, "Orta Risk")

    # ── KONTROL 7: SQL Injection Belirtileri (GET/POST parametrelerinde) ──
    for satir in satirlar[:3]:  # Sadece istek satirlarina bak
        if satir.startswith(("GET ", "POST ", "PUT ")):
            for kalip in SQL_INJECTION_KALIPLARI:
                if re.search(kalip, satir, re.IGNORECASE):
                    detay = (
                        f"[SQL INJECTION GIRIŞIMI] HTTP isteginde SQL injection kalıbı tespit edildi. "
                        f"İstek: '{satir[:120]}'. "
                        "Parametre sanitizasyonu ve prepared statement kullanilmali."
                    )
                    print(f"  [!!!] KRITIK | SQL Injection Girişimi -> {hedef_ip}")
                    kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                           "SQL Injection Girişimi", detay, "Kritik Risk")
                    break

    # ── KONTROL 8: XSS Belirtileri ───────────────────────────────────────
    for satir in satirlar[:5]:
        for kalip in XSS_KALIPLARI:
            if re.search(kalip, satir, re.IGNORECASE):
                detay = (
                    f"[XSS GIRIŞIMI] HTTP verisinde XSS kalıbı tespit edildi. "
                    f"Icerik: '{satir[:120]}'. "
                    "Girdi dogrulama, cikti encoding ve CSP basligi kullanilmali."
                )
                print(f"  [!!!] KRITIK | XSS Girişimi -> {hedef_ip}")
                kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                       "XSS (Cross-Site Scripting) Girişimi", detay, "Kritik Risk")
                break

    # ── KONTROL 9: Path Traversal / Directory Traversal ──────────────────
    for satir in satirlar[:3]:
        for kalip in PATH_TRAVERSAL_KALIPLARI:
            if re.search(kalip, satir, re.IGNORECASE):
                detay = (
                    f"[PATH TRAVERSAL] Dizin gecisi girişimi tespit edildi. "
                    f"İstek: '{satir[:120]}'. "
                    "Dosya yolu dogrulamasi ve sandbox kullanilmali."
                )
                print(f"  [!!!] KRITIK | Path Traversal -> {hedef_ip}")
                kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                       "Path Traversal / Directory Traversal", detay, "Kritik Risk")
                break

    # ── KONTROL 10: Hassas Bilgi Sizintisi ───────────────────────────────
    for kalip, (tur, risk) in HASSAS_BILGI_KALIPLARI.items():
        eslesme = re.search(kalip, metin, re.IGNORECASE)
        if eslesme:
            bulunan = eslesme.group(0)
            # Kredi karti ve sifre degerlerini kisalt (tam gosterme)
            if len(bulunan) > 20:
                bulunan = bulunan[:20] + "***"
            detay = (
                f"[HASSAS BILGI SIZINTISI] {tur} tespit edildi. "
                f"Deger (kisaltilmis): '{bulunan}'. "
                "Bu bilgi HTTP trafiğinde acik geciyor. HTTPS kullanilmali ve loglama kontrol edilmeli."
            )
            print(f"  [!] {risk} | {tur} Sizintisi -> {hedef_ip}")
            kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
                   f"Hassas Bilgi Sizintisi: {tur}", detay, risk)

    # ── KONTROL 11: HTTP Uzerinden Kimlik Dogrulama ──────────────────────
    auth = basliklar.get("Authorization", "")
    if auth and auth.startswith("Basic "):
        detay = (
            f"[HTTP BASIC AUTH] Kimlik dogrulama bilgisi sifreli olmayan HTTP "
            "uzerinden gonderiliyor. Base64 ile kodlanmis kullanici adi ve parola "
            "kolayca cozulebilir. HTTPS zorunlu kilinmali."
        )
        print(f"  [!] Yuksek Risk | HTTP Basic Auth -> {hedef_ip}")
        kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
               "Sifreli HTTP Uzerinden Basic Auth", detay, "Yuksek Risk")

    # ── KONTROL 12: X-Powered-By Bilgi Sizintisi ─────────────────────────
    powered_by = basliklar.get("X-Powered-By", "")
    if powered_by:
        detay = (
            f"[X-Powered-By SIZINTISI] Teknoloji bilgisi gorunur: '{powered_by}'. "
            "Saldirgan bu bilgiyle hedef sisteme ozel exploit arayabilir. "
            "Bu baslik sunucu konfigurasyonundan kaldirilmali."
        )
        print(f"  [~] Dusuk Risk | X-Powered-By Acik: {powered_by}")
        kaydet(kaynak_ip, hedef_ip, "HTTP", 80,
               "Teknoloji Bilgisi Sizintisi (X-Powered-By)", detay, "Dusuk Risk")

# ─────────────────────────────────────────
# PAKET ISLEYICI
# ─────────────────────────────────────────

def paket_isle(paket):
    if not paket.haslayer(IP):
        return

    kaynak = paket[IP].src
    hedef  = paket[IP].dst
    port   = None

    if paket.haslayer(TCP):
        port = bilinen_port_sec(paket[TCP].dport, paket[TCP].sport)
    elif paket.haslayer(UDP):
        port = bilinen_port_sec(paket[UDP].dport, paket[UDP].sport)

    protokol, risk, aciklama = port_siniflandir(port)
    zafiyet_turu = "Trafik Tespiti" if risk == "Bilgi" else f"Tehlikeli Port ({port})"

    print(f"[>] {kaynak} -> {hedef} | {protokol} | Port: {port} | {risk}")
    kaydet(kaynak, hedef, protokol, port, zafiyet_turu, aciklama, risk)

    # HTTP DPI: Port 80 sifresiz trafik - tum zafiyet kontrolleri
    if port == 80 and paket.haslayer(Raw):
        print(f"  [*] HTTP DPI basliyor -> {hedef}")
        http_analiz_et(kaynak, hedef, bytes(paket[Raw]))

    # TLS/SSL Surum Analizi: 443 ve diger sifreli portlar
    if port in HTTPS_PORTLAR and paket.haslayer(Raw):
        tls_analiz_et(kaynak, hedef, bytes(paket[Raw]), port)

# ─────────────────────────────────────────
# ANA BLOK
# ─────────────────────────────────────────

if __name__ == "__main__":
    csv_baslat()

    try:
        iface = conf.ifaces.dev_from_index(IFACE_INDEX)
        print(f"[+] Dinleme baslatiliyor -> Ag Karti: {iface}")
    except Exception as e:
        print(f"[HATA] Ag karti bulunamadi (Index: {IFACE_INDEX}): {e}")
        print("       from scapy.all import conf; conf.ifaces.show()")
        exit(1)

    print("[+] Tum IP trafigi taranıyor (HTTP, HTTPS, DNS, FTP, SSH, ...)")
    print("[+] TLS/SSL surum analizi AKTIF -> Port: 443, 8443, 465, 993, 995, 587")
    print("[+] HTTP DPI analizi AKTIF      -> Port: 80")
    print("[+] Aktif zafiyet kontrolleri   -> 12 farkli kontrol")
    print("[+] Paketler yakalaniyor... Durdurmak icin CTRL+C\n")

    sniff(iface=iface, prn=paket_isle, store=0, filter="ip")
