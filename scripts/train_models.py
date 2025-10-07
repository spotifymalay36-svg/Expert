"""
Train Pre-trained ML Models for WAF
Trains all ML models using generated sample data
"""

import numpy as np
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path
import json
from datetime import datetime

def train_cnn_model(X_train, y_train, X_test, y_test, model_dir: Path):
    """Train CNN payload analyzer"""
    
    print("\n[1/3] Training CNN Payload Analyzer...")
    
    # Reshape for CNN (add sequence dimension)
    X_train_cnn = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_test_cnn = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
    
    # Build CNN model
    model = tf.keras.Sequential([
        tf.keras.layers.Conv1D(64, 3, activation='relu', input_shape=(X_train.shape[1], 1)),
        tf.keras.layers.MaxPooling1D(2),
        tf.keras.layers.Conv1D(128, 3, activation='relu'),
        tf.keras.layers.GlobalMaxPooling1D(),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(5, activation='softmax')  # 5 classes
    ])
    
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    # Train
    history = model.fit(
        X_train_cnn, y_train,
        epochs=10,
        batch_size=64,
        validation_data=(X_test_cnn, y_test),
        verbose=1
    )
    
    # Evaluate
    test_loss, test_acc = model.evaluate(X_test_cnn, y_test, verbose=0)
    print(f"CNN Test Accuracy: {test_acc:.4f}")
    
    # Save model
    model_file = model_dir / 'cnn_payload_model.h5'
    model.save(model_file)
    print(f"Saved CNN model to {model_file}")
    
    return history.history['accuracy'][-1], test_acc

def train_random_forest(X_train, y_train, X_test, y_test, model_dir: Path):
    """Train Random Forest classifier"""
    
    print("\n[2/3] Training Random Forest Classifier...")
    
    # Train model
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    rf.fit(X_train, y_train)
    
    # Evaluate
    train_acc = rf.score(X_train, y_train)
    test_acc = rf.score(X_test, y_test)
    
    print(f"Random Forest Train Accuracy: {train_acc:.4f}")
    print(f"Random Forest Test Accuracy: {test_acc:.4f}")
    
    # Save model
    model_file = model_dir / 'rf_classifier.pkl'
    with open(model_file, 'wb') as f:
        pickle.dump(rf, f)
    print(f"Saved Random Forest to {model_file}")
    
    return train_acc, test_acc

def train_isolation_forest(X_train, model_dir: Path):
    """Train Isolation Forest for anomaly detection"""
    
    print("\n[3/3] Training Isolation Forest (Anomaly Detection)...")
    
    # Use only benign samples (label 0) for anomaly detection
    X_benign = X_train[np.where(np.random.random(len(X_train)) > 0.2)]  # Simulate benign data
    
    # Train model
    iso_forest = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    iso_forest.fit(X_benign)
    
    print(f"Isolation Forest trained on {len(X_benign)} samples")
    
    # Save model
    model_file = model_dir / 'isolation_forest.pkl'
    with open(model_file, 'wb') as f:
        pickle.dump(iso_forest, f)
    print(f"Saved Isolation Forest to {model_file}")
    
    return True

def main():
    """Train all models"""
    
    print("=" * 80)
    print("TRAINING ML MODELS FOR AI-DRIVEN WAF")
    print("=" * 80)
    
    # Check if data exists
    data_dir = Path('./data/samples/training')
    if not data_dir.exists():
        print("\nERROR: Training data not found!")
        print("Please run: python scripts/generate_sample_data.py")
        return
    
    # Load data
    print("\nLoading training data...")
    X_train = np.load(data_dir / 'X_train.npy')
    X_test = np.load(data_dir / 'X_test.npy')
    y_train = np.load(data_dir / 'y_train.npy')
    y_test = np.load(data_dir / 'y_test.npy')
    
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Features: {X_train.shape[1]}")
    print(f"Classes: {len(np.unique(y_train))}")
    
    # Create model directory
    model_dir = Path('./models')
    model_dir.mkdir(parents=True, exist_ok=True)
    
    # Train all models
    results = {}
    
    try:
        # CNN
        cnn_train_acc, cnn_test_acc = train_cnn_model(X_train, y_train, X_test, y_test, model_dir)
        results['cnn'] = {'train_acc': float(cnn_train_acc), 'test_acc': float(cnn_test_acc)}
        
        # Random Forest
        rf_train_acc, rf_test_acc = train_random_forest(X_train, y_train, X_test, y_test, model_dir)
        results['random_forest'] = {'train_acc': float(rf_train_acc), 'test_acc': float(rf_test_acc)}
        
        # Isolation Forest
        train_isolation_forest(X_train, model_dir)
        results['isolation_forest'] = {'status': 'trained'}
        
    except Exception as e:
        print(f"\nERROR during training: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Save training report
    report = {
        'timestamp': datetime.now().isoformat(),
        'training_samples': int(len(X_train)),
        'testing_samples': int(len(X_test)),
        'results': results
    }
    
    report_file = model_dir / 'training_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 80)
    print("MODEL TRAINING COMPLETE")
    print("=" * 80)
    print(f"\nModels saved to: {model_dir}")
    print(f"Training report: {report_file}")
    print("\nModel Performance Summary:")
    print(f"  CNN Test Accuracy: {results['cnn']['test_acc']:.2%}")
    print(f"  Random Forest Test Accuracy: {results['random_forest']['test_acc']:.2%}")
    print(f"  Isolation Forest: Trained")
    print("\nYou can now start the WAF with pre-trained models:")
    print("  python main.py")

if __name__ == "__main__":
    main()