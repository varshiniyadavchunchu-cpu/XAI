import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

# Selected subset of 20 key features matching CICIDS2017 for intrusion detection
FEATURE_COLUMNS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Max',
    'Fwd Header Length',
    'Bwd Header Length',
    'Packet Length Mean',
    'Average Packet Size'
]

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
DATA_FILE = os.path.join(DATA_DIR, 'cicids2017_sample.csv')
SCALER_FILE = os.path.join(DATA_DIR, 'scaler.joblib')
LABEL_ENCODER_FILE = os.path.join(DATA_DIR, 'label_encoder.joblib')

def generate_synthetic_data(num_samples=10000):
    """
    Generates a high-fidelity synthetic network traffic dataset mimicking CICIDS2017.
    Classes: BENIGN, DoS Hulk, DDoS, PortScan, FTP-Patator, SSH-Patator, Web Attack.
    """
    print(f"Generating {num_samples} synthetic network flows...")
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Reset seed to get organic new values on retrain request
    np.random.seed()
    
    # Introduce small random variation to overall sample count
    num_samples = num_samples + np.random.randint(-400, 400)
    
    # Calculate samples per class
    classes = ['BENIGN', 'DoS Hulk', 'DDoS', 'PortScan', 'FTP-Patator', 'SSH-Patator', 'Web Attack']
    class_ratios = [0.55, 0.15, 0.12, 0.08, 0.04, 0.04, 0.02]
    
    # Add random offset to counts
    class_counts = [int(num_samples * r) + np.random.randint(-25, 25) for r in class_ratios]
    
    # Adjust last class to make sure total equals dynamic num_samples
    class_counts[-1] = num_samples - sum(class_counts[:-1])
    
    data_list = []
    
    for label, count in zip(classes, class_counts):
        if count <= 0:
            continue
            
        # Initialize arrays for this class
        dest_ports = np.zeros(count, dtype=int)
        duration = np.zeros(count)
        tot_fwd_pkts = np.zeros(count, dtype=int)
        tot_bwd_pkts = np.zeros(count, dtype=int)
        tot_len_fwd_pkts = np.zeros(count)
        tot_len_bwd_pkts = np.zeros(count)
        fwd_pkt_len_max = np.zeros(count)
        fwd_pkt_len_min = np.zeros(count)
        fwd_pkt_len_mean = np.zeros(count)
        bwd_pkt_len_max = np.zeros(count)
        bwd_pkt_len_min = np.zeros(count)
        bwd_pkt_len_mean = np.zeros(count)
        flow_bytes_sec = np.zeros(count)
        flow_pkts_sec = np.zeros(count)
        flow_iat_mean = np.zeros(count)
        flow_iat_max = np.zeros(count)
        fwd_header_len = np.zeros(count, dtype=int)
        bwd_header_len = np.zeros(count, dtype=int)
        pkt_len_mean = np.zeros(count)
        avg_pkt_size = np.zeros(count)
        
        if label == 'BENIGN':
            # Benign traffic is split into a realistic mix to cover different flow types:
            # 50% Active HTTP/HTTPS (larger flows, medium duration)
            # 35% Short Queries/DNS/NTP (1-3 packets, very short duration, non-zero query payload size)
            # 15% Single-packet / Ephemeral flows (1 forward packet, 0 backward, non-zero size query)
            
            # Setup split indices
            idx_active = int(count * 0.50)
            idx_short = int(count * 0.35)
            idx_single = count - idx_active - idx_short
            
            # 1. Active traffic (larger TCP/UDP connections)
            ports_active = np.random.choice([80, 443, 8080, 3306], idx_active, p=[0.4, 0.45, 0.1, 0.05])
            duration_active = np.random.exponential(scale=5.0, size=idx_active) + 0.01
            tot_fwd_active = np.random.randint(4, 50, size=idx_active)
            tot_bwd_active = np.random.randint(4, 50, size=idx_active)
            
            fwd_min_active = np.random.choice([0, 40, 54], idx_active)
            fwd_max_active = np.random.randint(150, 1500, size=idx_active)
            fwd_mean_active = (fwd_max_active + fwd_min_active) / 2.0
            
            bwd_min_active = np.random.choice([0, 40, 54], idx_active)
            bwd_max_active = np.random.randint(150, 1500, size=idx_active)
            bwd_mean_active = (bwd_max_active + bwd_min_active) / 2.0
            
            # 2. Short queries (DNS queries on 53, NTP on 123, or simple HTTP api requests)
            ports_short = np.random.choice([53, 123, 443, 80], idx_short, p=[0.6, 0.2, 0.1, 0.1])
            duration_short = np.random.uniform(0.001, 0.15, size=idx_short)
            tot_fwd_short = np.random.randint(1, 4, size=idx_short)
            tot_bwd_short = np.random.randint(1, 3, size=idx_short)
            
            # Benign queries MUST carry data (unlike SYN scans)
            fwd_min_short = np.random.randint(40, 70, size=idx_short)
            fwd_max_short = np.random.randint(80, 300, size=idx_short)
            fwd_mean_short = (fwd_max_short + fwd_min_short) / 2.0
            
            bwd_min_short = np.random.randint(40, 70, size=idx_short)
            bwd_max_short = np.random.randint(80, 300, size=idx_short)
            bwd_mean_short = (bwd_max_short + bwd_min_short) / 2.0
            
            # 3. Single-packet / Ephemeral (DNS lookup failures, NTP check-ins)
            ports_single = np.random.choice([53, 123, 443, 80], idx_single, p=[0.7, 0.1, 0.1, 0.1])
            duration_single = np.random.uniform(0.0001, 0.005, size=idx_single)
            tot_fwd_single = np.ones(idx_single, dtype=int)
            tot_bwd_single = np.zeros(idx_single, dtype=int)
            
            fwd_min_single = np.random.randint(40, 60, size=idx_single)
            fwd_max_single = np.random.randint(60, 200, size=idx_single)
            fwd_mean_single = (fwd_max_single + fwd_min_single) / 2.0
            
            bwd_min_single = np.zeros(idx_single)
            bwd_max_single = np.zeros(idx_single)
            bwd_mean_single = np.zeros(idx_single)
            
            # Combine all subgroups
            dest_ports = np.concatenate([ports_active, ports_short, ports_single])
            duration = np.concatenate([duration_active, duration_short, duration_single])
            tot_fwd_pkts = np.concatenate([tot_fwd_active, tot_fwd_short, tot_fwd_single])
            tot_bwd_pkts = np.concatenate([tot_bwd_active, tot_bwd_short, tot_bwd_single])
            
            fwd_pkt_len_min = np.concatenate([fwd_min_active, fwd_min_short, fwd_min_single])
            fwd_pkt_len_max = np.concatenate([fwd_max_active, fwd_max_short, fwd_max_single])
            fwd_pkt_len_mean = np.concatenate([fwd_mean_active, fwd_mean_short, fwd_mean_single])
            
            bwd_pkt_len_min = np.concatenate([bwd_min_active, bwd_min_short, bwd_min_single])
            bwd_pkt_len_max = np.concatenate([bwd_max_active, bwd_max_short, bwd_max_single])
            bwd_pkt_len_mean = np.concatenate([bwd_mean_active, bwd_mean_short, bwd_mean_single])
            
            # Calculations
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = tot_bwd_pkts * bwd_pkt_len_mean
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / np.maximum(1, tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = duration * np.random.uniform(0.5, 0.95, size=count)
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = (tot_len_fwd_pkts + tot_len_bwd_pkts) / np.maximum(1, tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean * 1.1
            
        elif label == 'DoS Hulk':
            # DoS Hulk: high volume HTTP POST request flooding to port 80/443
            dest_ports = np.random.choice([80, 443], count)
            duration = np.random.uniform(10.0, 60.0, size=count) # Long duration flows
            tot_fwd_pkts = np.random.randint(500, 5000, size=count)
            tot_bwd_pkts = np.random.randint(1, 10, size=count) # Mostly one-sided
            
            fwd_pkt_len_min = np.random.randint(200, 400, size=count) # Large packets
            fwd_pkt_len_max = np.random.randint(600, 1200, size=count)
            fwd_pkt_len_mean = np.random.uniform(300, 500, size=count)
            
            bwd_pkt_len_min = np.zeros(count)
            bwd_pkt_len_max = np.random.choice([0, 60, 350], count, p=[0.7, 0.2, 0.1])
            bwd_pkt_len_mean = bwd_pkt_len_max * 0.5
            
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = tot_bwd_pkts * bwd_pkt_len_mean
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / (tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = np.random.uniform(0.1, 0.5, size=count) # Very constant small IAT
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = (tot_len_fwd_pkts + tot_len_bwd_pkts) / (tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean
            
        elif label == 'DDoS':
            # DDoS: Short flows, high frequency, random ports, heavy flow packets/s
            dest_ports = np.random.randint(1024, 65535, size=count)
            duration = np.random.uniform(0.001, 0.1, size=count) # Super short duration
            tot_fwd_pkts = np.random.randint(5, 50, size=count)
            tot_bwd_pkts = np.random.randint(0, 3, size=count)
            
            fwd_pkt_len_min = np.random.choice([0, 20, 40], count)
            fwd_pkt_len_max = np.random.randint(40, 100, size=count)
            fwd_pkt_len_mean = np.random.uniform(20, 50, size=count)
            
            bwd_pkt_len_min = np.zeros(count)
            bwd_pkt_len_max = np.random.choice([0, 40], count, p=[0.9, 0.1])
            bwd_pkt_len_mean = bwd_pkt_len_max * 0.1
            
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = tot_bwd_pkts * bwd_pkt_len_mean
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / (tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = duration * 0.9
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = (tot_len_fwd_pkts + tot_len_bwd_pkts) / np.maximum(1, tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean
            
        elif label == 'PortScan':
            # PortScan: Scans consecutive ports. Rapid connections, minimal data
            dest_ports = np.random.randint(1, 1024, size=count)
            duration = np.random.uniform(0.0001, 0.002, size=count) # Extremely short
            tot_fwd_pkts = np.random.choice([1, 2], count, p=[0.7, 0.3])
            tot_bwd_pkts = np.random.choice([0, 1], count, p=[0.8, 0.2])
            
            fwd_pkt_len_min = np.zeros(count)
            fwd_pkt_len_max = np.random.choice([0, 40], count, p=[0.9, 0.1])
            fwd_pkt_len_mean = fwd_pkt_len_max * 0.5
            
            bwd_pkt_len_min = np.zeros(count)
            bwd_pkt_len_max = np.zeros(count)
            bwd_pkt_len_mean = np.zeros(count)
            
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = np.zeros(count)
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / (tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = duration
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = tot_len_fwd_pkts / (tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean
            
        elif label == 'FTP-Patator' or label == 'SSH-Patator':
            # Brute force attacks on FTP (21) or SSH (22)
            dest_ports = np.full(count, 21 if label == 'FTP-Patator' else 22)
            duration = np.random.uniform(0.5, 3.0, size=count)
            tot_fwd_pkts = np.random.randint(10, 30, size=count)
            tot_bwd_pkts = np.random.randint(8, 25, size=count)
            
            fwd_pkt_len_min = np.random.choice([0, 20], count)
            fwd_pkt_len_max = np.random.choice([32, 64, 128], count)
            fwd_pkt_len_mean = (fwd_pkt_len_max + fwd_pkt_len_min) / 2.0
            
            bwd_pkt_len_min = np.random.choice([0, 20], count)
            bwd_pkt_len_max = np.random.choice([32, 64, 128], count)
            bwd_pkt_len_mean = (bwd_pkt_len_max + bwd_pkt_len_min) / 2.0
            
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = tot_bwd_pkts * bwd_pkt_len_mean
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / (tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = np.random.uniform(0.2, 1.0, size=count)
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = (tot_len_fwd_pkts + tot_len_bwd_pkts) / (tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean
            
        elif label == 'Web Attack':
            # Web Attack: HTTP GET/POST with specific SQLi/XSS payloads, large Fwd Length
            dest_ports = np.random.choice([80, 8080], count)
            duration = np.random.uniform(1.0, 10.0, size=count)
            tot_fwd_pkts = np.random.randint(5, 40, size=count)
            tot_bwd_pkts = np.random.randint(5, 40, size=count)
            
            # Payloads are large, pushing up Fwd Packet Length
            fwd_pkt_len_min = np.random.randint(150, 300, size=count)
            fwd_pkt_len_max = np.random.randint(1000, 2500, size=count)
            fwd_pkt_len_mean = np.random.uniform(400, 900, size=count)
            
            bwd_pkt_len_min = np.random.choice([0, 40], count)
            bwd_pkt_len_max = np.random.randint(100, 1000, size=count)
            bwd_pkt_len_mean = np.random.uniform(100, 400, size=count)
            
            tot_len_fwd_pkts = tot_fwd_pkts * fwd_pkt_len_mean
            tot_len_bwd_pkts = tot_bwd_pkts * bwd_pkt_len_mean
            
            flow_bytes_sec = (tot_len_fwd_pkts + tot_len_bwd_pkts) / duration
            flow_pkts_sec = (tot_fwd_pkts + tot_bwd_pkts) / duration
            flow_iat_mean = duration / (tot_fwd_pkts + tot_bwd_pkts)
            flow_iat_max = duration * 0.8
            
            fwd_header_len = tot_fwd_pkts * 20
            bwd_header_len = tot_bwd_pkts * 20
            
            pkt_len_mean = (tot_len_fwd_pkts + tot_len_bwd_pkts) / (tot_fwd_pkts + tot_bwd_pkts)
            avg_pkt_size = pkt_len_mean
            
        class_df = pd.DataFrame({
            'Destination Port': dest_ports,
            'Flow Duration': duration,
            'Total Fwd Packets': tot_fwd_pkts,
            'Total Backward Packets': tot_bwd_pkts,
            'Total Length of Fwd Packets': tot_len_fwd_pkts,
            'Total Length of Bwd Packets': tot_len_bwd_pkts,
            'Fwd Packet Length Max': fwd_pkt_len_max,
            'Fwd Packet Length Min': fwd_pkt_len_min,
            'Fwd Packet Length Mean': fwd_pkt_len_mean,
            'Bwd Packet Length Max': bwd_pkt_len_max,
            'Bwd Packet Length Min': bwd_pkt_len_min,
            'Bwd Packet Length Mean': bwd_pkt_len_mean,
            'Flow Bytes/s': flow_bytes_sec,
            'Flow Packets/s': flow_pkts_sec,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Max': flow_iat_max,
            'Fwd Header Length': fwd_header_len,
            'Bwd Header Length': bwd_header_len,
            'Packet Length Mean': pkt_len_mean,
            'Average Packet Size': avg_pkt_size,
            'Label': [label] * count
        })
        data_list.append(class_df)
        
    df = pd.concat(data_list, ignore_index=True)
    
    # Shuffle the dataset
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.to_csv(DATA_FILE, index=False)
    print(f"Dataset generated and saved to {DATA_FILE}")
    return df

def clean_and_prepare_data(df):
    """
    Cleans infinity/NaN values, splits dataset into X and y.
    """
    # Replace infinite values with NaN and then drop NaNs
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    X = df[FEATURE_COLUMNS].copy()
    y = df['Label'].copy()
    
    return X, y

def get_data_splits(test_size=0.2, num_samples=10000):
    """
    Loads dataset, creates split, and returns scaled inputs and encoders.
    """
    if not os.path.exists(DATA_FILE):
        df = generate_synthetic_data(num_samples)
    else:
        df = pd.read_csv(DATA_FILE)
        
    X, y = clean_and_prepare_data(df)
    
    # Initialize scaler and encoder
    scaler = StandardScaler()
    label_encoder = LabelEncoder()
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
    
    # Fit and transform
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_COLUMNS)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_COLUMNS)
    
    # Fit encoder
    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)
    
    # Save scaler and encoder
    os.makedirs(DATA_DIR, exist_ok=True)
    joblib.dump(scaler, SCALER_FILE)
    joblib.dump(label_encoder, LABEL_ENCODER_FILE)
    
    return X_train_scaled, X_test_scaled, y_train_encoded, y_test_encoded, label_encoder, X_train, X_test

def load_scaler_and_encoder():
    """
    Loads the saved scaler and label encoder.
    """
    if not os.path.exists(SCALER_FILE) or not os.path.exists(LABEL_ENCODER_FILE):
        raise FileNotFoundError("Scaler or LabelEncoder not found. Please train the model first.")
    scaler = joblib.load(SCALER_FILE)
    encoder = joblib.load(LABEL_ENCODER_FILE)
    return scaler, encoder

def preprocess_single_flow(flow_dict):
    """
    Takes a single network flow dict and prepares it for prediction using the saved scaler.
    """
    scaler, _ = load_scaler_and_encoder()
    
    # Extract only matching feature columns
    features = []
    for col in FEATURE_COLUMNS:
        val = flow_dict.get(col, 0.0)
        # Ensure numbers are valid
        try:
            val = float(val)
            if np.isnan(val) or np.isinf(val):
                val = 0.0
        except (ValueError, TypeError):
            val = 0.0
        features.append(val)
        
    features_array = np.array(features).reshape(1, -1)
    scaled_features = scaler.transform(features_array)
    
    # Return as DataFrame for SHAP explanation (preserves feature names)
    return pd.DataFrame(scaled_features, columns=FEATURE_COLUMNS), pd.DataFrame(features_array, columns=FEATURE_COLUMNS)
