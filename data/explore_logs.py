"""
Explore the network logs we generated.
This helps us understand the data before building models.
"""

import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the data
df = pd.read_csv('data/sample_logs/network_logs.csv')

logger.info("=" * 60)
logger.info("DATASET OVERVIEW")
logger.info("=" * 60)

# Basic info
logger.info(f"\nDataset shape: {df.shape[0]} rows, {df.shape[1]} columns")
logger.info(f"\nColumn names:\n{df.columns.tolist()}")

# Data types
logger.info(f"\nData types:\n{df.dtypes}")

# Missing values
logger.info(f"\nMissing values:\n{df.isnull().sum()}")

# Label distribution
logger.info("\n" + "=" * 60)
logger.info("LABEL DISTRIBUTION (What we're trying to detect)")
logger.info("=" * 60)
logger.info(f"\n{df['label'].value_counts()}")
logger.info(f"\nPercentages:\n{df['label'].value_counts(normalize=True) * 100}")

# Statistics for each label
logger.info("\n" + "=" * 60)
logger.info("COMPARING NORMAL vs ATTACK LOGS")
logger.info("=" * 60)

for label in df['label'].unique():
    subset = df[df['label'] == label]
    logger.info(f"\n{label.upper()}:")
    logger.info(f"  Count: {len(subset)}")
    logger.info(f"  Avg bytes sent: {subset['bytes_sent'].mean():.0f}")
    logger.info(f"  Avg bytes received: {subset['bytes_received'].mean():.0f}")
    logger.info(f"  Avg packet count: {subset['packet_count'].mean():.0f}")
    logger.info(f"  Avg duration: {subset['duration_seconds'].mean():.2f}s")
    logger.info(f"  % encrypted: {(subset['is_encrypted'].sum() / len(subset) * 100):.1f}%")

# Show examples
logger.info("\n" + "=" * 60)
logger.info("SAMPLE LOGS FROM EACH TYPE")
logger.info("=" * 60)

for label in df['label'].unique():
    logger.info(f"\n{label.upper()} example:")
    sample = df[df['label'] == label].iloc[0]
    for col in sample.index:
        logger.info(f"  {col}: {sample[col]}")

