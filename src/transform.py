"""
transform.py
============
Transformaciones y feature engineering sobre el dataset de logs de red.
Añade columnas derivadas que facilitan la detección de anomalías.

Uso:
    python src/transform.py
"""

import os
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

os.environ["HADOOP_HOME"] = r"C:\hadoop"


def create_spark_session() -> SparkSession:
    """Crea y devuelve una SparkSession configurada para modo local.

    Returns:
        SparkSession lista para usar.
    """
    spark = SparkSession.builder \
        .appName("network-anomaly-transform") \
        .master("local[*]") \
        .config("spark.sql.shuffle.partitions", "8") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")
    return spark


def add_time_features(df: DataFrame) -> DataFrame:
    """Extrae características temporales del timestamp.

    Args:
        df: DataFrame con columna timestamp de tipo TimestampType.

    Returns:
        DataFrame con columnas hour, day_of_week e is_off_hours añadidas.
    """
    return df \
        .withColumn("hour", F.hour("timestamp")) \
        .withColumn("day_of_week", F.dayofweek("timestamp")) \
        .withColumn("is_off_hours", F.col("hour").between(0, 6).cast("integer"))


def add_network_features(df: DataFrame) -> DataFrame:
    """Añade características derivadas del tráfico de red.

    Args:
        df: DataFrame con columnas bytes_sent, bytes_received y packets.

    Returns:
        DataFrame con columnas ratio_bytes, bytes_per_packet e
        is_internal_src añadidas.
    """
    return df \
        .withColumn(
            "ratio_bytes",
            F.when(F.col("bytes_received") > 0,
                   F.col("bytes_sent") / F.col("bytes_received"))
             .otherwise(F.lit(-1.0))
        ) \
        .withColumn(
            "bytes_per_packet",
            F.when(F.col("packets") > 0,
                   F.col("bytes_sent") / F.col("packets"))
             .otherwise(F.lit(0.0))
        ) \
        .withColumn(
            "is_internal_src",
            (F.col("src_ip").startswith("192.168.") |
             F.col("src_ip").startswith("10.0.")).cast("integer")
        )


def add_port_features(df: DataFrame) -> DataFrame:
    """Clasifica los puertos de destino en categorías conocidas.

    Args:
        df: DataFrame con columna dst_port.

    Returns:
        DataFrame con columna port_category añadida.
    """
    return df.withColumn(
        "port_category",
        F.when(F.col("dst_port") < 1024, "well_known")
         .when(F.col("dst_port") < 49152, "registered")
         .otherwise("ephemeral")
    )


def transform(df: DataFrame) -> DataFrame:
    """Aplica todas las transformaciones en secuencia.

    Args:
        df: DataFrame raw cargado desde ingest.

    Returns:
        DataFrame enriquecido con todas las features derivadas.
    """
    df = add_time_features(df)
    df = add_network_features(df)
    df = add_port_features(df)
    return df


if __name__ == "__main__":
    from ingest import create_spark_session, load_raw

    spark = create_spark_session()
    df_raw = load_raw(spark, "data/raw/network_logs.csv")
    df = transform(df_raw)

    print("\nSchema tras transformación:")
    df.printSchema()

    print("\nMuestra de columnas derivadas:")
    df.select(
        "timestamp", "hour", "is_off_hours",
        "ratio_bytes", "bytes_per_packet",
        "is_internal_src", "port_category", "label"
    ).show(10, truncate=False)

    spark.stop()