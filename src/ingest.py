"""
ingest.py
=========
Ingesta y validación inicial del dataset de logs de red.
Lee el CSV raw, aplica schema explícito y genera un informe básico de calidad.

Uso:
    python src/ingest.py
"""

import os
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, IntegerType, LongType, TimestampType
)

os.environ["HADOOP_HOME"] = r"C:\hadoop"


def create_spark_session() -> SparkSession:
    """Crea y devuelve una SparkSession configurada para modo local.

    Returns:
        SparkSession lista para usar.
    """
    spark = SparkSession.builder \
        .appName("network-anomaly-ingest") \
        .master("local[*]") \
        .config("spark.sql.shuffle.partitions", "8") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")
    return spark


def get_schema() -> StructType:
    """Define el schema explícito del CSV de logs de red.

    Returns:
        StructType con los campos y tipos del dataset.
    """
    return StructType([
        StructField("timestamp",      StringType(),  True),
        StructField("src_ip",         StringType(),  True),
        StructField("dst_ip",         StringType(),  True),
        StructField("src_port",       IntegerType(), True),
        StructField("dst_port",       IntegerType(), True),
        StructField("protocol",       StringType(),  True),
        StructField("bytes_sent",     LongType(),    True),
        StructField("bytes_received", LongType(),    True),
        StructField("duration_ms",    IntegerType(), True),
        StructField("packets",        IntegerType(), True),
        StructField("flag",           StringType(),  True),
        StructField("label",          StringType(),  True),
    ])


def load_raw(spark: SparkSession, path: str):
    """Lee el CSV raw y aplica el schema explícito.

    Args:
        spark: SparkSession activa.
        path: Ruta al archivo CSV.

    Returns:
        DataFrame con los datos cargados y timestamp parseado.
    """
    df = spark.read \
        .option("header", "true") \
        .option("nullValue", "") \
        .schema(get_schema()) \
        .csv(path)

    df = df.withColumn(
        "timestamp",
        F.to_timestamp("timestamp", "yyyy-MM-dd HH:mm:ss")
    )

    return df


def quality_report(df) -> None:
    """Imprime un informe básico de calidad del dataset.

    Args:
        df: DataFrame de PySpark a analizar.
    """
    total = df.count()
    print(f"\n{'='*50}")
    print(f"  INFORME DE CALIDAD — INGESTA")
    print(f"{'='*50}")
    print(f"  Total registros  : {total:,}")
    print(f"  Particiones      : {df.rdd.getNumPartitions()}")

    print("\n  Schema:")
    df.printSchema()

    print("  Distribución por label:")
    df.groupBy("label") \
      .count() \
      .withColumn("pct", F.round(F.col("count") / total * 100, 2)) \
      .orderBy("count", ascending=False) \
      .show()

    print("  Nulos por columna:")
    df.select([
        F.count(F.when(F.col(c).isNull(), c)).alias(c)
        for c in df.columns
    ]).show()

    print("  Estadísticas numéricas:")
    df.select(
        "bytes_sent", "bytes_received", "duration_ms", "packets"
    ).describe().show()


if __name__ == "__main__":
    spark = create_spark_session()
    df = load_raw(spark, "data/raw/network_logs.csv")
    quality_report(df)
    spark.stop()