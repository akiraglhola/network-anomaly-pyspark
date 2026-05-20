# Network Traffic Anomaly Detection with PySpark

A PySpark pipeline that processes **500K+ network flow records** and detects three types of security threats: port scans, DDoS attacks, and data exfiltration.

Built on hands-on experience with production network traffic analysis — where anomalies are rare, data is noisy, and false positives have real operational cost.

---

## What it does

Security teams analyzing network traffic face a needle-in-a-haystack problem: anomalous activity represents less than 1% of total traffic, buried inside hundreds of thousands of normal connections.

This pipeline automates detection using behavioral signatures — patterns that distinguish attacks from legitimate traffic regardless of IP or port — and exports results in Parquet format ready for downstream analysis.

---

## Pipeline

```
Raw CSV logs (500K+ rows)
        │
        ▼
   [ingest.py]       Schema validation · null checks · quality report
        │
        ▼
 [transform.py]      Feature engineering · time features · traffic ratios
        │
        ▼
  [detect.py]        Anomaly detection · GroupBy aggregations · thresholds
        │
        ▼
  [export.py]        Parquet output partitioned by protocol · summary CSV
```

---

## Detection results

| Attack | Logic | Result |
|---|---|---|
| **Port Scan** | One source IP hits >50 distinct ports/hour | 4/4 detected, 0 false positives |
| **DDoS** | >400 sources → same dest in off-hours, 0 response bytes | 1/1 detected, 0 false positives |
| **Exfiltration** | Internal IP sends >100MB outbound at night, ratio >100 | 2/2 detected, 0 false positives |

---

## Project structure

```
network-anomaly-pyspark/
├── src/
│   ├── generate_network_logs.py   # Synthetic NetFlow-style data generator
│   ├── ingest.py                  # Ingestion and schema validation
│   ├── transform.py               # Feature engineering
│   ├── detect.py                  # Anomaly detectors
│   └── export.py                  # Full pipeline + Parquet export
├── data/
│   ├── raw/                       # Input CSV (gitignored)
│   ├── processed/                 # Transformed data in Parquet
│   └── output/                    # Detection results
├── notebooks/
├── tests/
└── requirements.txt
```

---

## Quickstart

**Requirements:** Python 3.11 · Java 11

```bash
git clone https://github.com/akiraglhola/network-anomaly-pyspark.git
cd network-anomaly-pyspark

python -m venv .venv
source .venv/Scripts/activate  # Windows
pip install -r requirements.txt

# Generate synthetic dataset
python src/generate_network_logs.py --rows 500000 --output data/raw/network_logs.csv

# Run full pipeline
python src/export.py
```
--- 

## Documentation

API documentation can be generated locally from the docstrings using `pdoc`:

```bash
pip install pdoc
pdoc src/ingest.py src/transform.py src/detect.py src/export.py src/generate_network_logs.py --output-dir doc/
```

Then open `doc/index.html` in your browser.

---

## Technical decisions worth noting

**Explicit schema over inference** — defining `StructType` upfront avoids a double scan of the data and catches type mismatches at load time rather than mid-pipeline.

**Filter before GroupBy** — applying row-level filters before aggregation keeps derived columns available and reduces shuffle volume.

**Response bytes as DDoS signature** — threshold-based detection alone produced false positives at scale. Adding `bytes_sent_back == 0` eliminated them by encoding the actual semantics of server saturation rather than just counting sources.

**Pandas for small outputs** — the 3-row summary CSV is written with pandas instead of Spark, avoiding unnecessary overhead for non-distributed workloads.

---

## Tech stack

`PySpark 3.5` · `Python 3.11` · `pandas` · `numpy` · `Parquet / Snappy`

---

## Author

Akira Garcia · [GitHub](https://github.com/akiraglhola) · [LinkedIn](https://linkedin.com/in/akiragarcialuis)