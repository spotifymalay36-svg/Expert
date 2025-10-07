"""
Generate Sample Training Data and Pre-trained Models
Creates realistic threat data for demonstrations and pre-trains ML models
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pickle
import json
from pathlib import Path
from datetime import datetime, timedelta
import random

# Threat categories
THREAT_CATEGORIES = ['BENIGN', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'MALWARE']

def generate_sample_threat_data(num_samples: int = 10000) -> tuple:
    """Generate synthetic threat detection training data"""
    
    print(f"Generating {num_samples} sample threat data points...")
    
    features = []
    labels = []
    
    for i in range(num_samples):
        # Determine label (20% threats, 80% benign)
        label = random.choice([0, 0, 0, 0, random.randint(1, 4)])
        labels.append(label)
        
        # Generate features based on label
        if label == 0:  # BENIGN
            feature_vector = generate_benign_features()
        elif label == 1:  # SQL_INJECTION
            feature_vector = generate_sql_injection_features()
        elif label == 2:  # XSS
            feature_vector = generate_xss_features()
        elif label == 3:  # COMMAND_INJECTION
            feature_vector = generate_command_injection_features()
        else:  # MALWARE
            feature_vector = generate_malware_features()
        
        features.append(feature_vector)
    
    X = np.array(features, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    
    print(f"Generated {len(features)} samples")
    print(f"Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
    
    return X, y

def generate_benign_features() -> list:
    """Generate features for benign traffic"""
    return [
        random.uniform(10, 1000),  # payload_length
        random.uniform(100, 1500),  # string_length
        random.randint(1024, 65535),  # src_port
        random.choice([80, 443, 8080]),  # dst_port
        random.randint(0, 5),  # space_count
        random.randint(0, 3),  # equal_signs
        random.randint(0, 2),  # ampersands
        random.randint(0, 1),  # question_marks
        random.randint(0, 2),  # percent_signs
        random.randint(20, 50),  # unique_characters
        # N-gram features (benign)
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # No malicious keywords
        # Entropy features
        random.uniform(4.0, 5.5),  # Shannon entropy (normal)
        random.uniform(100, 500),  # byte_variance
        random.uniform(0.5, 0.9),  # compression_ratio
        # Protocol features
        1, 0, 1, 0, 0, random.randint(100, 1500)
    ]

def generate_sql_injection_features() -> list:
    """Generate features for SQL injection"""
    return [
        random.uniform(50, 500),  # payload_length
        random.uniform(200, 800),  # string_length
        random.randint(1024, 65535),  # src_port
        random.choice([80, 443, 3306]),  # dst_port
        random.randint(5, 20),  # space_count (more spaces)
        random.randint(3, 10),  # equal_signs (SQL has many)
        random.randint(1, 5),  # ampersands
        random.randint(0, 3),  # question_marks
        random.randint(0, 5),  # percent_signs
        random.randint(25, 60),  # unique_characters
        # N-gram features (SQL keywords present)
        random.randint(1, 3),  # 'script'
        random.randint(2, 5),  # 'select'
        random.randint(1, 3),  # 'union'
        random.randint(0, 2),  # 'insert'
        random.randint(0, 2),  # 'update'
        random.randint(0, 2),  # 'delete'
        0, 0, 0, 0, 0, 0,  # Other keywords
        # Entropy features
        random.uniform(5.5, 7.0),  # Higher entropy
        random.uniform(500, 1000),  # byte_variance
        random.uniform(0.3, 0.7),  # compression_ratio
        # Protocol features
        1, 0, 1, 0, 0, random.randint(100, 800)
    ]

def generate_xss_features() -> list:
    """Generate features for XSS attacks"""
    return [
        random.uniform(30, 400),  # payload_length
        random.uniform(150, 600),  # string_length
        random.randint(1024, 65535),  # src_port
        random.choice([80, 443, 8080]),  # dst_port
        random.randint(2, 15),  # space_count
        random.randint(1, 5),  # equal_signs
        random.randint(0, 3),  # ampersands
        random.randint(0, 2),  # question_marks
        random.randint(2, 8),  # percent_signs (encoding)
        random.randint(30, 70),  # unique_characters
        # N-gram features (script tags)
        random.randint(2, 5),  # 'script'
        0,  # 'select'
        0,  # 'union'
        0, 0, 0,  # SQL keywords
        random.randint(1, 3),  # 'exec'
        random.randint(0, 2),  # 'eval'
        0, 0, 0, 0,  # Other keywords
        # Entropy features
        random.uniform(5.0, 6.5),  # Entropy
        random.uniform(300, 700),  # byte_variance
        random.uniform(0.4, 0.8),  # compression_ratio
        # Protocol features
        1, 0, 1, 0, 0, random.randint(100, 600)
    ]

def generate_command_injection_features() -> list:
    """Generate features for command injection"""
    return [
        random.uniform(40, 350),  # payload_length
        random.uniform(180, 500),  # string_length
        random.randint(1024, 65535),  # src_port
        random.choice([80, 443, 22]),  # dst_port
        random.randint(3, 12),  # space_count
        random.randint(0, 3),  # equal_signs
        random.randint(1, 4),  # ampersands
        random.randint(0, 2),  # question_marks
        random.randint(1, 5),  # percent_signs
        random.randint(20, 50),  # unique_characters
        # N-gram features (command keywords)
        0, 0, 0, 0, 0, 0,  # No SQL keywords
        random.randint(1, 3),  # 'exec'
        random.randint(1, 3),  # 'eval'
        random.randint(1, 2),  # 'system'
        random.randint(0, 2),  # 'shell'
        random.randint(0, 1),  # 'cmd'
        random.randint(0, 1),  # 'powershell'
        # Entropy features
        random.uniform(5.2, 6.8),  # Entropy
        random.uniform(400, 800),  # byte_variance
        random.uniform(0.3, 0.7),  # compression_ratio
        # Protocol features
        1, 0, 1, 0, 0, random.randint(100, 500)
    ]

def generate_malware_features() -> list:
    """Generate features for malware traffic"""
    return [
        random.uniform(100, 2000),  # payload_length (can be large)
        random.uniform(500, 3000),  # string_length
        random.randint(1024, 65535),  # src_port
        random.randint(1024, 65535),  # dst_port (random high port)
        random.randint(0, 10),  # space_count
        random.randint(0, 2),  # equal_signs
        random.randint(0, 1),  # ampersands
        random.randint(0, 1),  # question_marks
        random.randint(0, 3),  # percent_signs
        random.randint(40, 90),  # unique_characters (high)
        # N-gram features (varied)
        random.randint(0, 1),  # 'script'
        0, 0, 0, 0, 0,  # SQL keywords
        random.randint(0, 2),  # 'exec'
        random.randint(0, 1),  # 'eval'
        random.randint(0, 1),  # 'system'
        0, 0, 0,  # Other keywords
        # Entropy features (high entropy = possibly encrypted)
        random.uniform(6.5, 7.8),  # Very high entropy
        random.uniform(800, 1500),  # byte_variance
        random.uniform(0.8, 1.0),  # Low compression (encrypted)
        # Protocol features
        random.choice([0, 1]), random.choice([0, 1]), 0, 0, 0, 
        random.randint(500, 2000)
    ]

def save_datasets(X, y, output_dir: Path):
    """Save datasets in various formats"""
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Save as NumPy arrays
    np.save(output_dir / 'X_train.npy', X_train)
    np.save(output_dir / 'X_test.npy', X_test)
    np.save(output_dir / 'y_train.npy', y_train)
    np.save(output_dir / 'y_test.npy', y_test)
    
    # Save as CSV for inspection
    df_train = pd.DataFrame(X_train)
    df_train['label'] = y_train
    df_train.to_csv(output_dir / 'train_data.csv', index=False)
    
    df_test = pd.DataFrame(X_test)
    df_test['label'] = y_test
    df_test.to_csv(output_dir / 'test_data.csv', index=False)
    
    # Save scaler
    scaler = StandardScaler()
    scaler.fit(X_train)
    with open(output_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    print(f"\nDatasets saved to {output_dir}")
    print(f"  - Training samples: {len(X_train)}")
    print(f"  - Testing samples: {len(X_test)}")
    print(f"  - Feature dimensions: {X_train.shape[1]}")

def generate_threat_intelligence_feed(output_dir: Path, num_iocs: int = 1000):
    """Generate sample threat intelligence IOCs"""
    
    print(f"\nGenerating {num_iocs} sample IOCs...")
    
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "file_hashes": []
    }
    
    # Generate malicious IPs
    for i in range(num_iocs // 4):
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        iocs["ip_addresses"].append({
            "value": ip,
            "category": random.choice(["malware", "c2", "phishing", "botnet"]),
            "confidence": random.uniform(0.7, 1.0),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat()
        })
    
    # Generate malicious domains
    tlds = ['.com', '.net', '.org', '.ru', '.cn', '.tk']
    suspicious_words = ['secure', 'account', 'verify', 'update', 'login', 'bank', 'paypal']
    
    for i in range(num_iocs // 4):
        domain = f"{random.choice(suspicious_words)}{random.randint(100, 999)}{random.choice(tlds)}"
        iocs["domains"].append({
            "value": domain,
            "category": random.choice(["phishing", "malware", "c2"]),
            "confidence": random.uniform(0.6, 0.95),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 60))).isoformat()
        })
    
    # Generate malicious URLs
    for i in range(num_iocs // 4):
        domain = f"{random.choice(suspicious_words)}{random.randint(100, 999)}{random.choice(tlds)}"
        path = f"/{random.choice(['login', 'verify', 'secure', 'update'])}.php"
        url = f"http://{domain}{path}"
        iocs["urls"].append({
            "value": url,
            "category": "phishing",
            "confidence": random.uniform(0.75, 1.0),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat()
        })
    
    # Generate file hashes
    for i in range(num_iocs // 4):
        hash_value = ''.join(random.choices('0123456789abcdef', k=64))
        iocs["file_hashes"].append({
            "value": hash_value,
            "algorithm": "sha256",
            "category": random.choice(["malware", "ransomware", "trojan"]),
            "confidence": random.uniform(0.8, 1.0),
            "first_seen": (datetime.now() - timedelta(days=random.randint(1, 120))).isoformat()
        })
    
    # Save IOCs
    output_file = output_dir / 'threat_intelligence_feed.json'
    with open(output_file, 'w') as f:
        json.dump(iocs, f, indent=2)
    
    print(f"Threat intelligence feed saved to {output_file}")
    print(f"  - IPs: {len(iocs['ip_addresses'])}")
    print(f"  - Domains: {len(iocs['domains'])}")
    print(f"  - URLs: {len(iocs['urls'])}")
    print(f"  - Hashes: {len(iocs['file_hashes'])}")

def generate_network_traffic_samples(output_dir: Path, num_samples: int = 1000):
    """Generate sample network traffic packets"""
    
    print(f"\nGenerating {num_samples} network traffic samples...")
    
    packets = []
    
    for i in range(num_samples):
        packet = {
            "timestamp": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).isoformat(),
            "src_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "dst_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 3306, 8080, 8443]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "size": random.randint(64, 1500),
            "flags": random.choice(["SYN", "ACK", "FIN", "PSH"]) if random.random() > 0.3 else None,
            "payload_sample": generate_sample_payload(random.randint(0, 4))
        }
        packets.append(packet)
    
    # Save packets
    output_file = output_dir / 'network_traffic_samples.json'
    with open(output_file, 'w') as f:
        json.dump(packets, f, indent=2)
    
    print(f"Network traffic samples saved to {output_file}")

def generate_sample_payload(threat_type: int) -> str:
    """Generate sample packet payload"""
    
    if threat_type == 0:  # Benign
        return "GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
    elif threat_type == 1:  # SQL Injection
        return "GET /user?id=1' OR '1'='1 HTTP/1.1\\r\\n"
    elif threat_type == 2:  # XSS
        return "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\\r\\n"
    elif threat_type == 3:  # Command Injection
        return "POST /exec HTTP/1.1\\r\\nContent: cmd=ls; cat /etc/passwd\\r\\n"
    else:  # Malware
        return "".join(random.choices('0123456789abcdef', k=200))

def main():
    """Generate all sample data"""
    
    print("=" * 80)
    print("GENERATING SAMPLE DATA FOR AI-DRIVEN WAF")
    print("=" * 80)
    
    # Create output directory
    data_dir = Path('./data/samples')
    
    # Generate training data
    X, y = generate_sample_threat_data(num_samples=10000)
    save_datasets(X, y, data_dir / 'training')
    
    # Generate threat intelligence
    generate_threat_intelligence_feed(data_dir / 'threat_intel', num_iocs=1000)
    
    # Generate network traffic samples
    generate_network_traffic_samples(data_dir / 'network_traffic', num_samples=1000)
    
    print("\n" + "=" * 80)
    print("SAMPLE DATA GENERATION COMPLETE")
    print("=" * 80)
    print(f"\nAll data saved to: {data_dir}")
    print("\nYou can now:")
    print("  1. Train ML models using the generated datasets")
    print("  2. Load threat intelligence into the WAF")
    print("  3. Use network traffic samples for testing")
    print("\nNext steps:")
    print("  python scripts/train_models.py  # Train ML models")
    print("  python main.py                   # Start WAF with sample data")

if __name__ == "__main__":
    main()