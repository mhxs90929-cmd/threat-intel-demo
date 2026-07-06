import streamlit as st
import pandas as pd
import random

st.set_page_config(page_title="Threat Intel Dashboard — Live Demo", page_icon="🌐", layout="wide")

random.seed(7)

st.title("🌐 Threat Intelligence Aggregation & Visualization — Live Demo")
st.caption(
    "Synthetic IOC data only — no real indicators, feeds, or organizations. "
    "Demonstrates the enrichment, scoring, and dashboard logic from a multi-feed CTI "
    "platform (AlienVault OTX, MISP, VirusTotal, Shodan in production)."
)

COUNTRIES = [
    ("Russia", 61.5, 105.3), ("China", 35.9, 104.2), ("Iran", 32.4, 53.7),
    ("Brazil", -14.2, -51.9), ("Vietnam", 14.1, 108.3), ("Nigeria", 9.1, 8.7),
    ("United States", 37.1, -95.7), ("Ukraine", 48.4, 31.2), ("India", 20.6, 78.9),
]
IOC_TYPES = ["IP", "Domain", "URL", "Hash", "Email"]
FEEDS = ["AlienVault OTX", "MISP", "VirusTotal", "Abuse.ch", "Shodan"]
TACTICS = [
    "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
    "DefenseEvasion", "CredentialAccess", "LateralMovement",
    "Collection", "Exfiltration", "Impact",
]


def gen_ioc(i):
    country, lat, lon = random.choice(COUNTRIES)
    lat += random.uniform(-3, 3)
    lon += random.uniform(-3, 3)
    feed_count = random.randint(1, 4)
    age_hours = random.randint(1, 240)
    reputation_hit = random.random() < 0.3

    # Weighted, continuous-ish scoring so results spread across the range
    # instead of clustering at the ceiling.
    feed_score = feed_count * 12               # max 48
    recency_score = max(0, 20 - (age_hours / 12))  # decays from 20 to 0 over 10 days
    reputation_score = 18 if reputation_hit else 0
    noise = random.uniform(0, 10)

    risk = round(min(97, max(8, feed_score + recency_score + reputation_score + noise)))
    return {
        "IOC": f"{random.choice(IOC_TYPES)}-{1000+i}",
        "Type": random.choice(IOC_TYPES),
        "Country": country,
        "lat": lat, "lon": lon,
        "Feeds Reporting": feed_count,
        "Source Feed": random.choice(FEEDS),
        "First Seen (hrs ago)": age_hours,
        "MITRE Tactic": random.choice(TACTICS),
        "Risk Score": risk,
    }


if "iocs" not in st.session_state:
    st.session_state.iocs = [gen_ioc(i) for i in range(50)]

if st.button("🔄 Refresh threat feed"):
    st.session_state.iocs = [gen_ioc(i) for i in range(50)]

df = pd.DataFrame(st.session_state.iocs)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Active IOCs", len(df))
m2.metric("Critical (score ≥ 75)", int((df["Risk Score"] >= 75).sum()))
m3.metric("Feeds integrated", df["Source Feed"].nunique())
m4.metric("Countries observed", df["Country"].nunique())

st.divider()

left, right = st.columns([2, 1])

with left:
    st.subheader("Global threat origin map")
    st.map(df[["lat", "lon"]], size=20)

    st.subheader("Priority triage queue")
    st.dataframe(
        df.sort_values("Risk Score", ascending=False)[
            ["IOC", "Type", "Country", "Source Feed", "Feeds Reporting", "MITRE Tactic", "Risk Score"]
        ],
        use_container_width=True,
        hide_index=True,
        height=350,
    )

with right:
    st.subheader("IOC type distribution")
    st.bar_chart(df["Type"].value_counts())

    st.subheader("MITRE ATT&CK tactic coverage")
    st.bar_chart(df["MITRE Tactic"].value_counts())

    st.subheader("Feed source breakdown")
    st.bar_chart(df["Source Feed"].value_counts())

with st.expander("How the Risk Score is calculated"):
    st.markdown("""
| Signal | Contribution |
|---|---|
| Number of reporting feeds | up to 48 pts (12 pts per feed) |
| IOC age (recency) | up to 20 pts, decaying linearly over 10 days |
| Reputation/blacklist hit | +18 if flagged |
| Randomized enrichment noise | 0–10 pts |

Scores are bounded between 8 and 97 so the triage queue always shows meaningful separation
between indicators, rather than clustering multiple IOCs at a shared ceiling.

In the production platform, this scoring runs continuously against live feeds (AlienVault OTX,
MISP, VirusTotal, Abuse.ch, Shodan), with additional enrichment from geolocation/ASN lookups,
WHOIS/domain age, and passive DNS correlation, plus PCAP cross-referencing via PyShark/Scapy
for beaconing detection.
""")

st.caption("Built by Aasia Nasir — Security Automation Engineer · Python, Threat Intelligence, MITRE ATT&CK, Streamlit")
