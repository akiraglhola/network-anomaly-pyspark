"""
detect.py
=========
Detección de anomalías en tráfico de red mediante agregaciones
y window functions de PySpark.

Detecta tres patrones:
    - Port scan: una IP origen escanea muchos puertos en poco tiempo.
    - DDoS: muchas IPs distintas apuntan al mismo destino.
    - Exfiltración: una IP interna saca grandes volúmenes en horario nocturno.

Uso:
    python src/detect.py
"""

import os
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.window import Window

os.environ["HADOOP_HOME"] = r"C:\hadoop"


def create_spark_session() -> SparkSession:
    """Crea y devuelve una SparkSession configurada para modo local.

    Returns:
        SparkSession lista para usar.
    """
    spark = SparkSession.builder \
        .appName("network-anomaly-detect") \
        .master("local[*]") \
        .config("spark.sql.shuffle.partitions", "8") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")
    return spark


def detect_port_scan(df: DataFrame) -> DataFrame:
    """Detecta posibles port scans por IP origen.

    Una IP se considera sospechosa si contacta más de 50 puertos
    distintos en una misma hora.

    Args:
        df: DataFrame transformado con columnas hour y src_ip.

    Returns:
        DataFrame con las IPs sospechosas de port scan,
        ordenado por puertos distintos descendente.
    """
    return df.groupBy("src_ip", "hour") \
        .agg(
            F.countDistinct("dst_port").alias("distinct_ports"),
            F.count("*").alias("total_connections"),
            F.avg("bytes_sent").alias("avg_bytes_sent"),
            F.first("label").alias("label")
        ) \
        .filter(F.col("distinct_ports") > 50) \
        .orderBy("distinct_ports", ascending=False)


def detect_ddos(df: DataFrame) -> DataFrame:
    """Detecta posibles ataques DDoS por IP destino.

    Una IP destino se considera víctima si recibe conexiones de más
    de 20 IPs origen distintas en una misma hora con volumen alto.

    Args:
        df: DataFrame transformado con columnas hour, dst_ip y bytes_sent.

    Returns:
        DataFrame con las IPs destino bajo posible ataque DDoS.
    """
    return df.filter(F.col("is_off_hours") == 1) \
        .groupBy("dst_ip", "hour") \
        .agg(
            F.countDistinct("src_ip").alias("distinct_sources"),
            F.sum("bytes_sent").alias("total_bytes_received"),
            F.sum("bytes_received").alias("total_bytes_sent_back"),
            F.count("*").alias("total_connections"),
            F.first("label").alias("label")
        ) \
        .filter(
            (F.col("distinct_sources") > 400) &
            (F.col("total_bytes_received") > 1_000_000) &
            (F.col("total_bytes_sent_back") == 0)
        ) \
        .orderBy("distinct_sources", ascending=False)


def detect_exfiltration(df: DataFrame) -> DataFrame:
    """Detecta posibles exfiltraciones de datos.

    Una IP interna se considera sospechosa si en horario nocturno
    envía más de 100MB al exterior con ratio de envío muy alto.

    Args:
        df: DataFrame transformado con columnas is_off_hours,
            is_internal_src y ratio_bytes.

    Returns:
        DataFrame con las IPs sospechosas de exfiltración.
    """
    return df.filter(
            (F.col("is_off_hours") == 1) &
            (F.col("is_internal_src") == 1)
        ) \
        .groupBy("src_ip", "dst_ip") \
        .agg(
            F.sum("bytes_sent").alias("total_bytes_sent"),
            F.avg("ratio_bytes").alias("avg_ratio_bytes"),
            F.count("*").alias("total_connections"),
            F.first("label").alias("label")
        ) \
        .filter(
            (F.col("total_bytes_sent") > 100_000_000) &
            (F.col("avg_ratio_bytes") > 100)
        ) \
        .orderBy("total_bytes_sent", ascending=False)


def detect_all(df: DataFrame) -> dict:
    """Ejecuta todos los detectores y devuelve los resultados.

    Args:
        df: DataFrame transformado.

    Returns:
        Diccionario con tres DataFrames: port_scan, ddos, exfiltration.
    """
    return {
        "port_scan":    detect_port_scan(df),
        "ddos":         detect_ddos(df),
        "exfiltration": detect_exfiltration(df),
    }


def print_results(results: dict) -> None:
    """Imprime un resumen de los resultados de detección.

    Args:
        results: Diccionario devuelto por detect_all.
    """
    labels = {
        "port_scan":    "PORT SCAN",
        "ddos":         "DDoS",
        "exfiltration": "EXFILTRACIÓN",
    }

    for key, df in results.items():
        count = df.count()
        print(f"\n{'='*50}")
        print(f"  {labels[key]} — {count} casos detectados")
        print(f"{'='*50}")
        df.show(10, truncate=False)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from ingest import load_raw
    from transform import transform

    spark = create_spark_session()

    df_raw = load_raw(spark, "data/raw/network_logs.csv")
    df = transform(df_raw)

    results = detect_all(df)
    print_results(results)

    spark.stop()