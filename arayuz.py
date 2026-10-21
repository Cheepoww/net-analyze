"""
arayuz.py - Siber Guvenlik Analiz Paneli (Dashboard) v2
Calistirma: streamlit run arayuz.py
"""

import streamlit as st
import pandas as pd
import os

# ─────────────────────────────────────────
# SAYFA YAPILAN DIRMASI
# ─────────────────────────────────────────

st.set_page_config(
    page_title="Siber Guvenlik Analiz Paneli",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ WAN Trafik & Zafiyet Analiz Paneli")
st.markdown(
    "Bu panel, `analiz.py` motorunun urettigi "
    "`kapsamli_analiz_raporu.csv` dosyasini okuyarak sonuclari gorsellestir."
)
st.divider()

# ─────────────────────────────────────────
# VERİ OKUMA
# ─────────────────────────────────────────

CSV_DOSYASI = "kapsamli_analiz_raporu.csv"

if not os.path.exists(CSV_DOSYASI):
    st.warning(
        "Henuz bir rapor dosyasi bulunamadi.\n\n"
        "Lutfen once `analiz.py` motorunu calistirin:\n"
        "```\npython analiz.py\n```"
    )
    st.stop()

try:
    df = pd.read_csv(CSV_DOSYASI, sep=";", encoding="utf-8-sig")
except Exception as e:
    st.error(f"CSV dosyasi okunamadi: {e}")
    st.stop()

if df.empty:
    st.info("Rapor dosyasi mevcut fakat henuz veri icermiyor.")
    st.stop()

# Sutun adlarini normalize et (bosluk ve buyuk/kucuk harf farki kaldir)
df.columns = df.columns.str.strip()

# Sutunlari dinamik bul (Turkce karakter encoding farki olsa da calisir)
def sutun_bul(df, anahtar_kelime):
    for col in df.columns:
        if anahtar_kelime.lower() in col.lower():
            return col
    return None

COL_ZAMAN    = sutun_bul(df, "zaman")
COL_KAYNAK   = sutun_bul(df, "kaynak")
COL_HEDEF    = sutun_bul(df, "hedef")
COL_PROTOKOL = sutun_bul(df, "protokol")
COL_PORT     = sutun_bul(df, "port")
COL_ZAFIYET  = sutun_bul(df, "zafiyet")
COL_DETAY    = sutun_bul(df, "detay")
COL_RISK     = sutun_bul(df, "risk")

# Bulunan sutunlari logla (debug)
with st.expander("🔧 Tespit Edilen Sutun Adlari (Debug)"):
    st.write(list(df.columns))

# ─────────────────────────────────────────
# OZET METRIKLER
# ─────────────────────────────────────────

toplam = len(df)

if COL_RISK:
    kritik = len(df[df[COL_RISK].astype(str).str.contains("Kritik", case=False, na=False)])
    yuksek = len(df[df[COL_RISK].astype(str).str.contains("Yuksek|Yüksek", case=False, na=False)])
    orta   = len(df[df[COL_RISK].astype(str).str.contains("Orta", case=False, na=False)])
    dusuk  = len(df[df[COL_RISK].astype(str).str.contains("Dusuk|Düşük", case=False, na=False)])
    bilgi  = len(df[df[COL_RISK].astype(str).str.contains("Bilgi", case=False, na=False)])
else:
    kritik = yuksek = orta = dusuk = bilgi = 0

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("📦 Toplam",      toplam)
col2.metric("🔴 Kritik",      kritik)
col3.metric("🟠 Yuksek",      yuksek)
col4.metric("🟡 Orta",        orta)
col5.metric("🟢 Dusuk",       dusuk)
col6.metric("🔵 Bilgi",       bilgi)

st.divider()

# ─────────────────────────────────────────
# SIDEBAR FILTRELER
# ─────────────────────────────────────────

st.sidebar.header("🔍 Filtreler")
filtrelenmis = df.copy()

if COL_RISK:
    risk_seviyeleri = ["Tumu"] + sorted(df[COL_RISK].dropna().unique().tolist())
    secili_risk = st.sidebar.selectbox("Risk Seviyesi", risk_seviyeleri)
    if secili_risk != "Tumu":
        filtrelenmis = filtrelenmis[filtrelenmis[COL_RISK] == secili_risk]

if COL_PROTOKOL:
    protokoller = ["Tumu"] + sorted(df[COL_PROTOKOL].dropna().unique().tolist())
    secili_protokol = st.sidebar.selectbox("Protokol", protokoller)
    if secili_protokol != "Tumu":
        filtrelenmis = filtrelenmis[filtrelenmis[COL_PROTOKOL] == secili_protokol]

if COL_ZAFIYET:
    zafiyet_turleri = ["Tumu"] + sorted(df[COL_ZAFIYET].dropna().unique().tolist())
    secili_zafiyet = st.sidebar.selectbox("Zafiyet Turu", zafiyet_turleri)
    if secili_zafiyet != "Tumu":
        filtrelenmis = filtrelenmis[filtrelenmis[COL_ZAFIYET] == secili_zafiyet]

# ─────────────────────────────────────────
# VERİ TABLOSU
# ─────────────────────────────────────────

st.subheader(f"📋 Tespit Kayitlari ({len(filtrelenmis)} kayit gosteriliyor)")

# Risk sutununa renk uygula
def risk_rengi(val):
    val_str = str(val).lower()
    if "kritik"  in val_str: return "background-color:#ff4b4b;color:white;font-weight:bold;"
    if "yuksek"  in val_str or "yüksek" in val_str: return "background-color:#ff8c00;color:white;"
    if "orta"    in val_str: return "background-color:#ffa500;color:white;"
    if "dusuk"   in val_str or "düşük" in val_str:  return "background-color:#ffd700;color:black;"
    if "bilgi"   in val_str: return "background-color:#4b9dff;color:white;"
    return ""

if COL_RISK:
    styled_df = filtrelenmis.style.applymap(risk_rengi, subset=[COL_RISK])
    st.dataframe(styled_df, use_container_width=True, height=400)
else:
    st.dataframe(filtrelenmis, use_container_width=True, height=400)

st.divider()

# ─────────────────────────────────────────
# GRAFIKLER
# ─────────────────────────────────────────

g1, g2 = st.columns(2)

with g1:
    st.subheader("📊 Zafiyet Turu Dagilimi")
    if COL_ZAFIYET:
        st.bar_chart(filtrelenmis[COL_ZAFIYET].value_counts())

with g2:
    st.subheader("📊 Risk Seviyesi Dagilimi")
    if COL_RISK:
        st.bar_chart(filtrelenmis[COL_RISK].value_counts())

st.subheader("📊 Protokol Bazinda Trafik Dagilimi")
if COL_PROTOKOL:
    st.bar_chart(filtrelenmis[COL_PROTOKOL].value_counts())

# ─────────────────────────────────────────
# INDIRME BUTONU
# ─────────────────────────────────────────

st.divider()
csv_indir = filtrelenmis.to_csv(sep=";", index=False, encoding="utf-8-sig")
st.download_button(
    label="📥 Filtrelenmis Raporu CSV Olarak Indir",
    data=csv_indir.encode("utf-8-sig"),
    file_name="filtreli_rapor.csv",
    mime="text/csv"
)

st.caption("🛡️ WAN Trafik Analiz Araci | Siber Guvenlik Paneli")
