import pandas as pd
import numpy as np
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_DIR = BASE_DIR / "data" / "train"
TEST_DIR = BASE_DIR / "data" / "test"
OUTPUT_DIR = BASE_DIR / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Maximum training samples per class
SAMPLES_PER_CLASS = 30000


def load_csv(file_path, label, training=True):
    print(f"Loading {file_path.name}...")

    df = pd.read_csv(file_path, low_memory=False)

    if training and len(df) > SAMPLES_PER_CLASS:
        df = df.sample(
            n=SAMPLES_PER_CLASS,
            random_state=42
        )

    df["Label"] = label

    print(f"Selected records: {len(df)}")

    return df


def prepare_dataset(folder, training=True):
    suffix = "train" if training else "test"

    benign = load_csv(
        folder / f"Benign_{suffix}.pcap.csv",
        label=0,
        training=training
    )

    attack = load_csv(
        folder / f"ARP_Spoofing_{suffix}.pcap.csv",
        label=1,
        training=training
    )

    df = pd.concat(
        [benign, attack],
        ignore_index=True
    )

    features = df.columns.drop("Label")

    df[features] = df[features].apply(
        pd.to_numeric,
        errors="coerce"
    )

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    df[features] = df[features].fillna(0)

    df = df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    return df


print("\nPreparing improved training dataset...")

train_df = prepare_dataset(
    TRAIN_DIR,
    training=True
)

print("\nPreparing testing dataset...")

test_df = prepare_dataset(
    TEST_DIR,
    training=False
)

assert train_df.columns.tolist() == test_df.columns.tolist()

train_df.to_csv(
    OUTPUT_DIR / "train_processed.csv",
    index=False
)

test_df.to_csv(
    OUTPUT_DIR / "test_processed.csv",
    index=False
)

print("\n===== PREPROCESSING COMPLETED =====")

print("\nTraining records:", len(train_df))
print("Testing records:", len(test_df))

print("\nTraining class distribution:")
print(train_df["Label"].value_counts())

print("\nTesting class distribution:")
print(test_df["Label"].value_counts())