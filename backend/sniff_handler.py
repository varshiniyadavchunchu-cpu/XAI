import time
import threading
import random
import traceback
from collections import defaultdict
import numpy as np

# Try importing scapy
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class TrafficSniffer:
    def __init__(self):
        self.flows = []
        self.is_running = False
        self.thread = None
        self.lock = threading.Lock()
        self.fallback_mode = not SCAPY_AVAILABLE
        self.flow_buffer = defaultdict(list) # To track live packets if scapy is running
        self.simulate_attacks = True
        
        
    def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        self.flows = []
        self.flow_buffer.clear()
        
        if self.fallback_mode:
            print("Scapy not available. Starting Traffic Simulator fallback...")
            self.thread = threading.Thread(target=self._run_simulator, daemon=True)
        else:
            print("Attempting to start live Scapy sniffing...")
            self.thread = threading.Thread(target=self._run_sniffer, daemon=True)
            
        self.thread.start()
        
    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        print("Traffic sniffer/simulator stopped.")

    def get_recent_flows(self, limit=100):
        with self.lock:
            # Return copy of flows
            return list(self.flows[-limit:])
            
    def _run_simulator(self):
        """
        Simulates realistic network traffic flows, injecting occasional attacks.
        """
        attack_types = ['DoS Hulk', 'DDoS', 'PortScan', 'FTP-Patator', 'SSH-Patator', 'Web Attack']
        attacker_ips = ['192.168.1.150', '10.0.0.99', '172.16.5.40', '185.190.140.23']
        victim_ips = ['192.168.1.10', '192.168.1.12', '10.0.0.5', '10.0.0.6']
        
        while self.is_running:
            # Decide whether to generate normal flow or attack flow
            # 85% normal, 15% attack (if enabled)
            is_attack = (random.random() < 0.15) if self.simulate_attacks else False
            
            src_ip = f"192.168.1.{random.randint(20, 100)}"
            dst_ip = random.choice(victim_ips)
            timestamp = time.strftime('%H:%M:%S')
            
            if not is_attack:
                label = 'BENIGN'
                proto = random.choice(['TCP', 'UDP', 'TCP'])
                dest_port = random.choice([80, 443, 53, 8080, 3306, 123])
                
                # Simulating different benign sub-distributions
                if dest_port in [53, 123]: # Short DNS / NTP query
                    duration = random.uniform(0.002, 0.08)
                    tot_fwd = random.randint(1, 2)
                    tot_bwd = random.choice([1, 2])
                    
                    # Short queries must have data payloads (not empty like portscan)
                    fwd_len_min = random.randint(40, 60)
                    fwd_len_max = random.randint(80, 200)
                    fwd_len_mean = (fwd_len_min + fwd_len_max) / 2.0
                    
                    bwd_len_min = random.randint(40, 60)
                    bwd_len_max = random.randint(80, 200)
                    bwd_len_mean = (bwd_len_min + bwd_len_max) / 2.0
                elif random.random() < 0.2: # Single-packet / Ephemeral
                    duration = random.uniform(0.0001, 0.004)
                    tot_fwd = 1
                    tot_bwd = 0
                    
                    fwd_len_min = random.randint(40, 60)
                    fwd_len_max = random.randint(60, 150)
                    fwd_len_mean = (fwd_len_min + fwd_len_max) / 2.0
                    
                    bwd_len_min = 0
                    bwd_len_max = 0
                    bwd_len_mean = 0
                else: # Regular HTTP/HTTPS / DB active traffic
                    duration = random.uniform(0.1, 8.0)
                    tot_fwd = random.randint(4, 40)
                    tot_bwd = random.randint(4, 40)
                    
                    fwd_len_max = random.randint(150, 1460)
                    fwd_len_min = random.choice([0, 40, 54])
                    fwd_len_mean = random.uniform(fwd_len_min, fwd_len_max * 0.7)
                    
                    bwd_len_max = random.randint(150, 1460)
                    bwd_len_min = random.choice([0, 40, 54])
                    bwd_len_mean = random.uniform(bwd_len_min, bwd_len_max * 0.7)
                
            else:
                label = random.choice(attack_types)
                src_ip = random.choice(attacker_ips)
                
                if label == 'DoS Hulk':
                    proto = 'TCP'
                    dest_port = random.choice([80, 443])
                    duration = random.uniform(12.0, 55.0)
                    tot_fwd = random.randint(600, 4000)
                    tot_bwd = random.randint(1, 8)
                    fwd_len_min = random.randint(250, 350)
                    fwd_len_max = random.randint(700, 1100)
                    fwd_len_mean = random.uniform(300, 450)
                    bwd_len_min = 0
                    bwd_len_max = random.choice([0, 60, 350])
                    bwd_len_mean = bwd_len_max * 0.5
                    
                elif label == 'DDoS':
                    proto = 'TCP'
                    dest_port = random.randint(1024, 65535)
                    duration = random.uniform(0.002, 0.08)
                    tot_fwd = random.randint(8, 60)
                    tot_bwd = random.choice([0, 1, 2])
                    fwd_len_min = random.choice([0, 20])
                    fwd_len_max = random.randint(40, 90)
                    fwd_len_mean = random.uniform(20, 45)
                    bwd_len_min = 0
                    bwd_len_max = random.choice([0, 40])
                    bwd_len_mean = bwd_len_max * 0.1
                    
                elif label == 'PortScan':
                    proto = 'TCP'
                    dest_port = random.randint(20, 1024)
                    duration = random.uniform(0.0001, 0.0015)
                    tot_fwd = random.choice([1, 2])
                    tot_bwd = random.choice([0, 1])
                    fwd_len_min = 0
                    fwd_len_max = random.choice([0, 40])
                    fwd_len_mean = fwd_len_max * 0.5
                    bwd_len_min = 0
                    bwd_len_max = 0
                    bwd_len_mean = 0
                    
                elif label in ['FTP-Patator', 'SSH-Patator']:
                    proto = 'TCP'
                    dest_port = 21 if label == 'FTP-Patator' else 22
                    duration = random.uniform(0.6, 2.5)
                    tot_fwd = random.randint(11, 28)
                    tot_bwd = random.randint(9, 22)
                    fwd_len_min = random.choice([0, 20])
                    fwd_len_max = random.choice([32, 64, 128])
                    fwd_len_mean = (fwd_len_min + fwd_len_max) / 2
                    bwd_len_min = random.choice([0, 20])
                    bwd_len_max = random.choice([32, 64, 128])
                    bwd_len_mean = (bwd_len_min + bwd_len_max) / 2
                    
                else: # Web Attack
                    proto = 'TCP'
                    dest_port = random.choice([80, 8080])
                    duration = random.uniform(1.2, 8.5)
                    tot_fwd = random.randint(6, 35)
                    tot_bwd = random.randint(6, 35)
                    fwd_len_min = random.randint(180, 280)
                    fwd_len_max = random.randint(1200, 2400)
                    fwd_len_mean = random.uniform(500, 850)
                    bwd_len_min = random.choice([0, 40])
                    bwd_len_max = random.randint(200, 800)
                    bwd_len_mean = random.uniform(150, 350)
            
            tot_len_fwd = tot_fwd * fwd_len_mean
            tot_len_bwd = tot_bwd * bwd_len_mean
            
            flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / duration
            flow_pkts_sec = (tot_fwd + tot_bwd) / duration
            flow_iat_mean = duration / (tot_fwd + tot_bwd)
            flow_iat_max = duration * random.uniform(0.6, 0.95)
            
            fwd_header_len = tot_fwd * 20
            bwd_header_len = tot_bwd * 20
            pkt_len_mean = (tot_len_fwd + tot_len_bwd) / (tot_fwd + tot_bwd)
            avg_pkt_size = pkt_len_mean * 1.05
            
            flow_data = {
                'Timestamp': timestamp,
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Protocol': proto,
                'Destination Port': int(dest_port),
                'Flow Duration': float(duration),
                'Total Fwd Packets': int(tot_fwd),
                'Total Backward Packets': int(tot_bwd),
                'Total Length of Fwd Packets': float(tot_len_fwd),
                'Total Length of Bwd Packets': float(tot_len_bwd),
                'Fwd Packet Length Max': float(fwd_len_max),
                'Fwd Packet Length Min': float(fwd_len_min),
                'Fwd Packet Length Mean': float(fwd_len_mean),
                'Bwd Packet Length Max': float(bwd_len_max),
                'Bwd Packet Length Min': float(bwd_len_min),
                'Bwd Packet Length Mean': float(bwd_len_mean),
                'Flow Bytes/s': float(flow_bytes_sec),
                'Flow Packets/s': float(flow_pkts_sec),
                'Flow IAT Mean': float(flow_iat_mean),
                'Flow IAT Max': float(flow_iat_max),
                'Fwd Header Length': int(fwd_header_len),
                'Bwd Header Length': int(bwd_header_len),
                'Packet Length Mean': float(pkt_len_mean),
                'Average Packet Size': float(avg_pkt_size),
                'SimulatedLabel': label # Useful for dashboard correlation
            }
            
            with self.lock:
                self.flows.append(flow_data)
                # Cap the storage size
                if len(self.flows) > 500:
                    self.flows.pop(0)
                    
            # Wait random interval before next flow
            time.sleep(random.uniform(0.5, 2.5))
            
    def _run_sniffer(self):
        """
        Uses scapy.sniff to capture live packets and groups them into flows.
        """
        try:
            # We define a packet handler callback
            def packet_callback(pkt):
                if not self.is_running:
                    return
                
                if IP in pkt:
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst
                    proto_num = pkt[IP].proto
                    proto = 'TCP' if proto_num == 6 else ('UDP' if proto_num == 17 else 'OTHER')
                    
                    sport = pkt.sport if hasattr(pkt, 'sport') else 0
                    dport = pkt.dport if hasattr(pkt, 'dport') else 0
                    
                    # Create unique flow keys in both directions
                    flow_key = (ip_src, sport, ip_dst, dport, proto)
                    rev_key = (ip_dst, dport, ip_src, sport, proto)
                    
                    pkt_len = len(pkt)
                    curr_time = time.time()
                    
                    with self.lock:
                        # Find if this packet belongs to a forward or backward flow
                        is_fwd = True
                        target_key = flow_key
                        
                        if rev_key in self.flow_buffer:
                            is_fwd = False
                            target_key = rev_key
                            
                        flow = self.flow_buffer[target_key]
                        
                        # Add packet info
                        flow.append({
                            'time': curr_time,
                            'len': pkt_len,
                            'is_fwd': is_fwd
                        })
                        
                        # Process flows that have enough packets or duration
                        # To keep it simple, we process the flow when it has > 10 packets or exceeds 2 seconds
                        flow_duration = curr_time - flow[0]['time']
                        if len(flow) >= 15 or (flow_duration > 2.0 and len(flow) >= 3):
                            # Compile features for this flow
                            compiled_flow = self._compile_flow_features(target_key, flow)
                            self.flows.append(compiled_flow)
                            
                            # Clean buffer
                            del self.flow_buffer[target_key]
                            
                            # Cap the storage size
                            if len(self.flows) > 500:
                                self.flows.pop(0)

            # Start Scapy sniff (sniffs TCP/UDP traffic)
            sniff(filter="ip", prn=packet_callback, store=0, stop_filter=lambda x: not self.is_running)
            
        except Exception as e:
            print(f"Scapy sniffing encountered error: {e}")
            traceback.print_exc()
            print("Switching to Traffic Simulator fallback...")
            self.fallback_mode = True
            self._run_simulator()
            
    def _compile_flow_features(self, flow_key, packet_list):
        """
        Compiles list of packet metrics into a standard flow dictionary.
        """
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        fwd_packets = [p for p in packet_list if p['is_fwd']]
        bwd_packets = [p for p in packet_list if not p['is_fwd']]
        
        tot_fwd = len(fwd_packets)
        tot_bwd = len(bwd_packets)
        
        times = [p['time'] for p in packet_list]
        duration = max(times) - min(times) if len(times) > 1 else 0.001
        
        fwd_lens = [p['len'] for p in fwd_packets] if fwd_packets else [0]
        bwd_lens = [p['len'] for p in bwd_packets] if bwd_packets else [0]
        
        tot_len_fwd = sum(fwd_lens)
        tot_len_bwd = sum(bwd_lens)
        
        fwd_len_max = max(fwd_lens)
        fwd_len_min = min(fwd_lens)
        fwd_len_mean = np.mean(fwd_lens)
        
        bwd_len_max = max(bwd_lens)
        bwd_len_min = min(bwd_lens)
        bwd_len_mean = np.mean(bwd_lens)
        
        flow_bytes_sec = (tot_len_fwd + tot_len_bwd) / duration
        flow_pkts_sec = (tot_fwd + tot_bwd) / duration
        
        iats = np.diff(times) if len(times) > 1 else [0]
        flow_iat_mean = np.mean(iats)
        flow_iat_max = np.max(iats)
        
        # Scapy packet default headers are roughly 20 bytes
        fwd_header_len = tot_fwd * 20
        bwd_header_len = tot_bwd * 20
        
        all_lens = fwd_lens + bwd_lens
        pkt_len_mean = np.mean(all_lens)
        avg_pkt_size = pkt_len_mean * 1.05
        
        return {
            'Timestamp': time.strftime('%H:%M:%S', time.localtime(min(times))),
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': proto,
            'Destination Port': int(dport),
            'Flow Duration': float(duration),
            'Total Fwd Packets': int(tot_fwd),
            'Total Backward Packets': int(tot_bwd),
            'Total Length of Fwd Packets': float(tot_len_fwd),
            'Total Length of Bwd Packets': float(tot_len_bwd),
            'Fwd Packet Length Max': float(fwd_len_max),
            'Fwd Packet Length Min': float(fwd_len_min),
            'Fwd Packet Length Mean': float(fwd_len_mean),
            'Bwd Packet Length Max': float(bwd_len_max),
            'Bwd Packet Length Min': float(bwd_len_min),
            'Bwd Packet Length Mean': float(bwd_len_mean),
            'Flow Bytes/s': float(flow_bytes_sec),
            'Flow Packets/s': float(flow_pkts_sec),
            'Flow IAT Mean': float(flow_iat_mean),
            'Flow IAT Max': float(flow_iat_max),
            'Fwd Header Length': int(fwd_header_len),
            'Bwd Header Length': int(bwd_header_len),
            'Packet Length Mean': float(pkt_len_mean),
            'Average Packet Size': float(avg_pkt_size),
            'SimulatedLabel': 'BENIGN' # Will be overwritten by model prediction anyway
        }

# Singleton instance
global_sniffer = TrafficSniffer()
