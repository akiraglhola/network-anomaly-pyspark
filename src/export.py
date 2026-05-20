"""
export.py
=========
Exportación de resultados a formato Parquet y generación de
resumen ejecutivo en CSV.

El pipeline completo lee los datos raw, aplica transformaciones,
ejecuta los detectores y persiste los resultados en data/output/.

Uso:
    python src/export.py
"""

import os
import sys
sys.path.insert(0, "src")

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from ingest import load_raw
from transform import transform
from detect import detect_all

os.environ["HADOOP_HOME"] = r"C:\hadoop"


def create_spark_session() -> SparkSession:
    """Crea y devuelve una SparkSession configurada para modo local.

    Returns:
        SparkSession lista para usar.
    """
    spark = SparkSession.builder \
        .appName("network-anomaly-export") \
        .master("local[*]") \
        .config("spark.sql.shuffle.partitions", "8") \
        .getOrCreate()

    spark.sparkContext.setLogLevel("ERROR")
    return spark


def save_parquet(df: DataFrame, path: str, partition_by: str = None) -> None:
    """Guarda un DataFrame en formato Parquet.

    Args:
        df: DataFrame a guardar.
        path: Ruta de destino.
        partition_by: Columna por la que particionar, opcional.
    """
    writer = df.write.mode("overwrite")
    if partition_by:
        writer = writer.partitionBy(partition_by)
    writer.parquet(path)
    print(f"  Guardado en {path}")


def save_summary_csv(results: dict, path: str) -> None:
    """Guarda el resumen de detección como CSV usando pandas.

    Args:
        results: Diccionario con los DataFrames de resultados.
        path: Ruta de destino del archivo CSV.
    """
    import pandas as pd
    import os

    rows = [(name, df.count()) for name, df in results.items()]
    pdf = pd.DataFrame(rows, columns=["anomaly_type", "cases_detected"])

    os.makedirs(path, exist_ok=True)
    pdf.to_csv(f"{path}/summary.csv", index=False)
    print(f"  Guardado en {path}/summary.csv")


if __name__ == "__main__":
    spark = create_spark_session()

    print("\n[1/4] Cargando datos raw...")
    df_raw = load_raw(spark, "data/raw/network_logs.csv")

    print("[2/4] Aplicando transformaciones...")
    df = transform(df_raw)

    print("[3/4] Ejecutando detectores...")
    results = detect_all(df)

    print("[4/4] Exportando resultados...\n")

    # Dataset completo transformado en Parquet, particionado por protocolo
    save_parquet(
        df,
        "data/processed/network_logs_transformed",
        partition_by="protocol"
    )

    # Resultados de cada detector en Parquet
    for name, result_df in results.items():
        save_parquet(result_df, f"data/output/{name}")

    # Resumen ejecutivo en CSV
    save_summary_csv(results, "data/output/summary")

    print("\nPipeline completado. Resultados en data/output/")
    spark.stop()