"""
train_model.py
==============
Deep Learning IDS — PyTorch Training Script
--------------------------------------------
TRAIN ONCE → SAVE → NEVER RETRAIN.

This script:
1. Loads all CICIDS 2017 CSV files from dataset/ folder
2. Cleans and preprocesses the data
3. Uses SMOTE to balance the classes (fixes false alerts)
4. Selects top 20 features via SelectKBest
5. Scales features with RobustScaler (handles packet size outliers)
6. Trains a CNN + Bidirectional LSTM + Attention model in PyTorch
7. Uses AdamW optimizer + ReduceLROnPlateau + EarlyStopping
8. Tunes the classification threshold for minimum false alerts
9. Saves everything to saved_model/

After this runs successfully, just use:
    python app.py
"""

import os
import sys
import math
import time
import pickle
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, precision_recall_curve, classification_report
)
from imblearn.over_sampling import SMOTE

from config import (
    DATASET_DIR, MODEL_DIR, MODEL_PATH, SCALER_PATH,
    FEATURES_PATH, ENCODER_PATH, THRESHOLD_PATH,
    EPOCHS, BATCH_SIZE, TEST_SPLIT, K_FEATURES,
)

# ─── Device Setup ─────────────────────────────────────────────────────────────
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"\n{'='*60}")
print(f"  Deep Learning IDS — Training Script")
print(f"  Training on: {device}")
if device.type == 'cuda':
    print(f"  GPU: {torch.cuda.get_device_name(0)}")
print(f"{'='*60}\n")


# ─── Model Architecture ───────────────────────────────────────────────────────
class IDS_Model(nn.Module):
    def __init__(self, input_size):
        super(IDS_Model, self).__init__()

        # CNN layers for local feature extraction
        self.conv1 = nn.Conv1d(1, 64, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.pool  = nn.MaxPool1d(2)
        self.bn1   = nn.BatchNorm1d(64)
        self.bn2   = nn.BatchNorm1d(128)

        # Compute LSTM input size after pooling
        lstm_in = input_size // 2

        # Bidirectional LSTM for temporal pattern learning
        self.lstm = nn.LSTM(
            input_size=128,   # matches conv2 output channels
            hidden_size=128,
            num_layers=2,
            batch_first=True,
            dropout=0.3,
            bidirectional=True,
        )

        # Attention mechanism — focus on important attack features
        self.attention = nn.Linear(256, 1)

        # Fully connected classifier
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 1)

        # Regularization
        self.dropout = nn.Dropout(0.4)
        self.relu    = nn.ReLU()
        self.bn3     = nn.BatchNorm1d(128)
        self.bn4     = nn.BatchNorm1d(64)

    def forward(self, x):
        # CNN: (batch, 1, features)
        x = x.unsqueeze(1)
        x = self.relu(self.bn1(self.conv1(x)))
        x = self.relu(self.bn2(self.conv2(x)))
        # Pool: halve the feature dimension
        x = self.pool(x)

        # LSTM: expects (batch, seq_len, features)
        x = x.permute(0, 2, 1)
        x, _ = self.lstm(x)

        # Attention: weighted sum over time steps
        attn_weights = torch.softmax(self.attention(x), dim=1)
        x = torch.sum(attn_weights * x, dim=1)

        # Classification head
        x = self.relu(self.bn3(self.fc1(x)))
        x = self.dropout(x)
        x = self.relu(self.bn4(self.fc2(x)))
        x = self.dropout(x)
        x = self.fc3(x)   # raw logit — no sigmoid here (BCEWithLogitsLoss)
        return x


# ─── Step 1: Load Dataset ─────────────────────────────────────────────────────
def load_dataset():
    print("[1/7] Loading dataset...")
    csv_files = [
        os.path.join(DATASET_DIR, f)
        for f in os.listdir(DATASET_DIR)
        if f.endswith('.csv')
    ]
    if not csv_files:
        print(f"  ERROR: No CSV files found in '{DATASET_DIR}/'")
        sys.exit(1)

    dfs = []
    for i, path in enumerate(csv_files, 1):
        print(f"  [{i}/{len(csv_files)}] Reading {os.path.basename(path)}")
        df = pd.read_csv(path, low_memory=False)
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    print(f"  Loaded {len(df):,} rows from {len(csv_files)} files.\n")
    return df


# ─── Step 2: Preprocessing ────────────────────────────────────────────────────
def preprocess(df):
    print("[2/7] Preprocessing data...")
    # Normalize column names
    df.columns = df.columns.str.strip()

    # Find label column
    label_col = None
    for col in df.columns:
        if col.strip().lower() == 'label':
            label_col = col
            break
    if label_col is None:
        print("  ERROR: No 'Label' column found in the dataset!")
        print(f"  Available columns: {list(df.columns[:10])}")
        sys.exit(1)

    # Encode labels: BENIGN = 0, everything else = 1
    df[label_col] = df[label_col].astype(str).str.strip().str.upper()
    df['target'] = (df[label_col] != 'BENIGN').astype(int)
    df.drop(columns=[label_col], inplace=True)

    # Keep only numeric columns
    df = df.select_dtypes(include=[np.number])

    # Clean
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    # Remove constant columns
    nunique = df.nunique()
    constant_cols = nunique[nunique <= 1].index.tolist()
    df.drop(columns=[c for c in constant_cols if c != 'target'], inplace=True)

    print(f"  Clean dataset: {len(df):,} rows, {df.shape[1]} columns")
    print(f"  Attack rate:   {df['target'].mean()*100:.1f}% attack / "
          f"{(1 - df['target'].mean())*100:.1f}% benign\n")
    return df


# ─── Step 3: Feature Selection + Balancing ───────────────────────────────────
def select_and_balance(df):
    print("[3/7] Feature selection (SelectKBest) + SMOTE balancing...")
    y = df['target'].values
    X = df.drop(columns=['target']).values
    feature_names_all = df.drop(columns=['target']).columns.tolist()

    # Feature selection
    k = min(K_FEATURES, X.shape[1])
    selector = SelectKBest(score_func=f_classif, k=k)
    X_selected = selector.fit_transform(X, y)
    selected_mask = selector.get_support()
    selected_features = [feature_names_all[i]
                         for i, m in enumerate(selected_mask) if m]
    print(f"  Selected {k} features out of {X.shape[1]}")

    # SMOTE — over-sample minority (attack) class
    print("  Applying SMOTE to balance classes (this may take a minute)...")
    sm = SMOTE(random_state=42)
    X_bal, y_bal = sm.fit_resample(X_selected, y)
    print(f"  After SMOTE: {len(X_bal):,} samples "
          f"({y_bal.sum():,} attack / {(y_bal==0).sum():,} benign)\n")
    return X_bal, y_bal, selected_features


# ─── Step 4: Scale ────────────────────────────────────────────────────────────
def scale(X_train, X_val):
    print("[4/7] Scaling with RobustScaler...")
    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)
    print("  Scaler fitted.\n")
    return X_train, X_val, scaler


# ─── Step 5: Training ─────────────────────────────────────────────────────────
def train(X_train, y_train, X_val, y_val, input_size):
    print(f"[5/7] Training CNN+BiLSTM+Attention model on {device}...")

    # Tensors
    Xtr = torch.FloatTensor(X_train)
    ytr = torch.FloatTensor(y_train).unsqueeze(1)
    # Keep val on CPU — load batch-by-batch to avoid OOM
    Xvl_t = torch.FloatTensor(X_val)
    yvl_t = torch.FloatTensor(y_val).unsqueeze(1)

    train_ds = TensorDataset(Xtr, ytr)
    val_ds   = TensorDataset(Xvl_t, yvl_t)
    train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE,
                          shuffle=True, num_workers=0, pin_memory=(device.type=='cuda'))
    val_dl   = DataLoader(val_ds, batch_size=BATCH_SIZE,
                          shuffle=False, num_workers=0)

    model = IDS_Model(input_size).to(device)

    # Weighted loss to penalise false positives more
    pos_weight = torch.tensor([0.3]).to(device)
    criterion  = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, patience=3, factor=0.5
    )

    # Early stopping
    PATIENCE      = 5
    best_val_loss = math.inf
    patience_cnt  = 0
    best_state    = None

    for epoch in range(1, EPOCHS + 1):
        model.train()
        epoch_loss = 0.0
        for Xb, yb in train_dl:
            Xb, yb = Xb.to(device), yb.to(device)
            optimizer.zero_grad()
            out  = model(Xb)
            loss = criterion(out, yb)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        # Batched validation — avoids OOM on large val sets
        model.eval()
        val_loss_total = 0.0
        val_preds_all  = []
        with torch.no_grad():
            for Xb, yb in val_dl:
                Xb, yb = Xb.to(device), yb.to(device)
                out = model(Xb)
                val_loss_total += criterion(out, yb).item()
                val_preds_all.append((torch.sigmoid(out) >= 0.5).cpu().numpy())

        val_loss = val_loss_total / max(len(val_dl), 1)
        val_pred = np.concatenate(val_preds_all).flatten()
        val_acc  = accuracy_score(y_val, val_pred)

        avg_loss = epoch_loss / max(len(train_dl), 1)
        print(f"  Epoch {epoch:02d}/{EPOCHS}  "
              f"Loss={avg_loss:.4f}  "
              f"Val_Loss={val_loss:.4f}  "
              f"Val_Acc={val_acc:.4f}")

        scheduler.step(val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state    = {k: v.clone() for k, v in model.state_dict().items()}
            patience_cnt  = 0
        else:
            patience_cnt += 1
            if patience_cnt >= PATIENCE:
                print(f"\n  Early stopping at epoch {epoch}!\n")
                break

    # Restore best weights
    if best_state:
        model.load_state_dict(best_state)

    return model


# ─── Step 6: Threshold Tuning ─────────────────────────────────────────────────
def tune_threshold(model, X_val, y_val):
    print("[6/7] Tuning classification threshold...")
    model.eval()
    # Batched inference to avoid OOM
    val_ds = TensorDataset(torch.FloatTensor(X_val))
    val_dl = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False)
    all_probs = []
    with torch.no_grad():
        for (Xb,) in val_dl:
            Xb   = Xb.to(device)
            prob = torch.sigmoid(model(Xb)).cpu().numpy().flatten()
            all_probs.append(prob)
    probs = np.concatenate(all_probs)

    precisions, recalls, thresholds = precision_recall_curve(y_val, probs)

    # Find threshold: precision > 95% AND recall > 90%
    best_threshold = 0.5
    best_score = 0.0
    for p, r, t in zip(precisions[:-1], recalls[:-1], thresholds):
        if p > 0.95 and r > 0.90:
            score = p * r
            if score > best_score:
                best_score = score
                best_threshold = float(t)

    print(f"  Best threshold found: {best_threshold:.4f}")
    # Final metrics at best threshold
    final_preds = (probs >= best_threshold).astype(int)
    print(f"\n  === Final Test Metrics ===")
    print(f"  Accuracy : {accuracy_score(y_val, final_preds)*100:.2f}%")
    print(f"  Precision: {precision_score(y_val, final_preds)*100:.2f}%")
    print(f"  Recall   : {recall_score(y_val, final_preds)*100:.2f}%")
    print(f"  F1 Score : {f1_score(y_val, final_preds)*100:.2f}%\n")
    return best_threshold


# ─── Step 7: Save ─────────────────────────────────────────────────────────────
def save_all(model, scaler, features, threshold, input_size):
    print("[7/7] Saving model and preprocessing objects...")
    os.makedirs(MODEL_DIR, exist_ok=True)

    torch.save({
        'model_state_dict':    model.state_dict(),
        'input_size':          input_size,
        'model_architecture':  'CNN_BiLSTM_Attention',
    }, MODEL_PATH)

    pickle.dump(scaler,    open(SCALER_PATH,    'wb'))
    pickle.dump(features,  open(FEATURES_PATH,  'wb'))
    pickle.dump(threshold, open(THRESHOLD_PATH, 'wb'))

    print(f"\n  Saved to '{MODEL_DIR}/':")
    print(f"    ids_model.pth  — PyTorch CNN+BiLSTM+Attention")
    print(f"    scaler.pkl     — RobustScaler")
    print(f"    features.pkl   — {len(features)} selected features")
    print(f"    threshold.pkl  — {threshold:.4f} (tuned threshold)")
    print(f"\n{'='*60}")
    print(f"  Training complete! Run 'python app.py' to start.")
    print(f"{'='*60}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if os.path.exists(MODEL_PATH):
        print(f"  Model already exists at '{MODEL_PATH}'.")
        ans = input("  Retrain anyway? [y/N]: ").strip().lower()
        if ans != 'y':
            print("  Exiting. Use 'python app.py' to start the dashboard.")
            sys.exit(0)

    start = time.time()

    df                      = load_dataset()
    df                      = preprocess(df)
    X, y, selected_features = select_and_balance(df)
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=TEST_SPLIT, random_state=42, stratify=y
    )
    X_train, X_val, scaler  = scale(X_train, X_val)
    input_size               = X_train.shape[1]
    model                    = train(X_train, y_train, X_val, y_val, input_size)
    best_threshold           = tune_threshold(model, X_val, y_val)
    save_all(model, scaler, selected_features, best_threshold, input_size)

    print(f"  Total time: {(time.time()-start)/60:.1f} minutes")
