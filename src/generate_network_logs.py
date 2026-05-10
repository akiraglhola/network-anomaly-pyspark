"""
generate_network_logs.py
========================
Genera un dataset sintético de logs de tráfico de red estilo NetFlow.
Incluye tráfico normal y tres tipos de anomalías: port scan, DDoS y exfiltración.

Uso:
    python src/generate_network_logs.py --rows 500000 --output data/raw/network_logs.csv
"""

import argparse
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

INTERNAL_SUBNETS = ["192.168.1.", "192.168.2.", "10.0.0.", "10.0.1."]
EXTERNAL_IPS = [f"203.{r}.{s}.{t}" for r in range(10, 60)
                for s in range(1, 5) for t in range(1, 10)]

COMMON_PORTS = {
    "TCP": [80, 443, 22, 3306, 5432, 8080, 8443, 25, 587, 993],
    "UDP": [53, 123, 161, 514, 1194],
    "ICMP": [0],
}
PROTOCOLS = ["TCP", "UDP", "ICMP"]
TCP_FLAGS = ["SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH-ACK"]

HOUR_WEIGHTS = [
    0.2, 0.1, 0.1, 0.1, 0.1, 0.2,
    0.5, 1.5, 3.0, 4.0, 4.5, 4.0,
    3.5, 4.0, 4.5, 4.0, 3.5, 3.0,
    2.0, 1.5, 1.0, 0.8, 0.5, 0.3,
]
HOUR_WEIGHTS = np.array(HOUR_WEIGHTS) / sum(HOUR_WEIGHTS)


def random_internal_ip():
    subnet = random.choice(INTERNAL_SUBNETS)
    return subnet + str(random.randint(2, 254))


def random_external_ip():
    return random.choice(EXTERNAL_IPS)


def random_ip():
    return random_internal_ip() if random.random() < 0.7 else random_external_ip()


def generate_normal_record(base_time: datetime) -> dict:
    hour = np.random.choice(24, p=HOUR_WEIGHTS)
    offset_seconds = random.randint(0, 3599)
    ts = base_time + timedelta(hours=int(hour), seconds=offset_seconds)

    protocol = random.choices(PROTOCOLS, weights=[0.7, 0.2, 0.1])[0]
    dst_port = random.choice(COMMON_PORTS[protocol])
    src_port = random.randint(1024, 65535)

    bytes_sent = int(np.random.lognormal(mean=8, sigma=2))
    bytes_received = int(np.random.lognormal(mean=10, sigma=2))
    duration_ms = int(np.random.exponential(scale=300))
    packets = max(1, int(bytes_sent / random.randint(500, 1500)))

    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": random_ip(),
        "dst_ip": random_ip(),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "duration_ms": duration_ms,
        "packets": packets,
        "flag": random.choice(TCP_FLAGS) if protocol == "TCP" else "N/A",
        "label": "normal",
    }


def generate_port_scan(base_time: datetime, n_records: int = 200) -> list[dict]:
    attacker_ip = random_external_ip()
    victim_ip = random_internal_ip()
    start = base_time + timedelta(hours=random.randint(0, 23))
    records = []

    for i in range(n_records):
        ts = start + timedelta(seconds=i * random.uniform(0.05, 0.5))
        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.randint(1, 65535),
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 80),
            "bytes_received": 0,
            "duration_ms": random.randint(1, 30),
            "packets": 1,
            "flag": "SYN",
            "label": "port_scan",
        })
    return records


def generate_ddos(base_time: datetime, n_records: int = 500) -> list[dict]:
    victim_ip = random_internal_ip()
    start = base_time + timedelta(hours=random.randint(0, 22))
    records = []

    for _ in range(n_records):
        ts = start + timedelta(seconds=random.uniform(0, 60))
        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": random_external_ip(),
            "dst_ip": victim_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443]),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(1000, 65000),
            "bytes_received": 0,
            "duration_ms": random.randint(10, 200),
            "packets": random.randint(10, 500),
            "flag": random.choice(["SYN", "ACK"]),
            "label": "ddos",
        })
    return records


def generate_exfiltration(base_time: datetime, n_records: int = 50) -> list[dict]:
    insider_ip = random_internal_ip()
    external_ip = random_external_ip()
    start = base_time + timedelta(hours=2, minutes=random.randint(0, 59))
    records = []

    for i in range(n_records):
        ts = start + timedelta(minutes=i * 2)
        bytes_sent = random.randint(50_000_000, 200_000_000)
        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": insider_ip,
            "dst_ip": external_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 8443, 22]),
            "protocol": "TCP",
            "bytes_sent": bytes_sent,
            "bytes_received": random.randint(200, 2000),
            "duration_ms": random.randint(5000, 30000),
            "packets": bytes_sent // random.randint(1000, 9000),
            "flag": "PSH-ACK",
            "label": "exfiltration",
        })
    return records


def generate_dataset(n_normal: int, output_path: str, days: int = 7):
    base_date = datetime(2024, 3, 11)
    all_records = []

    print(f"[1/4] Generando {n_normal:,} registros normales...")
    for day in range(days):
        day_base = base_date + timedelta(days=day)
        day_records = n_normal // days
        all_records.extend(generate_normal_record(day_base) for _ in range(day_records))

    print("[2/4] Inyectando anomalías...")
    for day in range(days):
        day_base = base_date + timedelta(days=day)
        if day % 2 == 0:
            all_records.extend(generate_port_scan(day_base, n_records=200))
        if day % 3 == 0:
            all_records.extend(generate_ddos(day_base, n_records=500))
        if day % 4 == 0:
            all_records.extend(generate_exfiltration(day_base, n_records=50))

    print("[3/4] Mezclando y ordenando por timestamp...")
    df = pd.DataFrame(all_records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    total = len(df)
    anomaly_pct = (df["label"] != "normal").sum() / total * 100
    print(f"\n  Total registros : {total:,}")
    print(f"  Normales        : {(df['label'] == 'normal').sum():,}")
    print(f"  Port scan       : {(df['label'] == 'port_scan').sum():,}")
    print(f"  DDoS            : {(df['label'] == 'ddos').sum():,}")
    print(f"  Exfiltración    : {(df['label'] == 'exfiltration').sum():,}")
    print(f"  % anomalías     : {anomaly_pct:.2f}%\n")

    print(f"[4/4] Guardando en {output_path} ...")
    df.to_csv(output_path, index=False)
    print("  Listo.")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador de logs de red simulados")
    parser.add_argument("--rows", type=int, default=500_000,
                        help="Número de registros normales (default: 500000)")
    parser.add_argument("--days", type=int, default=7,
                        help="Días simulados (default: 7)")
    parser.add_argument("--output", type=str, default="data/raw/network_logs.csv",
                        help="Ruta de salida del CSV")
    args = parser.parse_args()

    generate_dataset(n_normal=args.rows, output_path=args.output, days=args.days)