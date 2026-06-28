"""
Generate synthetic network logs for anomaly detection.

This script creates realistic network traffic logs with both
normal behavior and injected attack patterns.

Author: Yazid Rahmouni
Date: 2026
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import logging

# Set up logging (so we can see what's happening)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkLogGenerator:
    """Generate realistic network traffic logs."""
    
    def __init__(self, n_records=10000, seed=42):
        """
        Initialize the generator.
        
        Args:
            n_records: How many logs to generate
            seed: Random seed (for reproducibility)
        """
        self.n_records = n_records
        self.seed = seed
        np.random.seed(seed)
        random.seed(seed)
        
        # Define network ranges
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        self.external_ips = [f"8.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(100)]
        self.safe_ports = [80, 443, 22, 25, 53, 3306, 5432]  # Common services
        self.all_ports = list(range(1, 65536))
    
    def generate_normal_logs(self, n_logs):
        """
        Generate normal, benign network traffic.
        
        Represents: Regular web browsing, email, cloud services
        """
        logger.info(f"Generating {n_logs} normal logs...")
        
        logs = []
        start_time = datetime(2024, 6, 1, 0, 0, 0)
        
        for i in range(n_logs):
            # Random timestamp
            timestamp = start_time + timedelta(
                seconds=random.randint(0, 86400*30)  # 30 days of data
            )
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source_ip': random.choice(self.internal_ips),
                'dest_ip': random.choice(self.external_ips),
                'source_port': random.randint(49152, 65535),  # Ephemeral ports
                'dest_port': random.choice(self.safe_ports),  # Normal ports
                'protocol': random.choice(['TCP', 'UDP']),
                'bytes_sent': np.random.gamma(shape=2, scale=1000),  # Realistic distribution
                'bytes_received': np.random.gamma(shape=2, scale=1000),
                'packet_count': np.random.randint(10, 500),
                'duration_seconds': np.random.exponential(scale=5),
                'flags': random.choice(['SYN,ACK', 'ACK', 'FIN', 'SYN,ACK,FIN']),
                'is_encrypted': random.choice([True, True, True, False]),  # 75% encrypted
                'label': 'normal'
            }
            logs.append(log)
        
        return pd.DataFrame(logs)
    
    def generate_port_scanning_logs(self, n_logs):
        """
        Generate port scanning attack logs.
        
        Pattern: One IP tries to connect to many different ports on target
        """
        logger.info(f"Generating {n_logs} port scanning logs...")
        
        logs = []
        start_time = datetime(2024, 6, 1, 0, 0, 0)
        attacker_ip = "192.168.1.150"  # Suspicious internal IP
        target_ip = random.choice(self.external_ips)
        
        for i in range(n_logs):
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400*30))
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source_ip': attacker_ip,  # Same source (suspicious!)
                'dest_ip': target_ip,      # Same target
                'source_port': random.randint(49152, 65535),
                'dest_port': random.choice(self.all_ports),  # Random ports (suspicious!)
                'protocol': 'TCP',
                'bytes_sent': 0,  # Port scans send minimal data
                'bytes_received': 0,
                'packet_count': 1,  # Just probe packets
                'duration_seconds': 0.1,  # Very brief
                'flags': 'SYN',  # Incomplete connections
                'is_encrypted': False,
                'label': 'port_scan'
            }
            logs.append(log)
        
        return pd.DataFrame(logs)
    
    def generate_ddos_logs(self, n_logs):
        """
        Generate DDoS attack logs.
        
        Pattern: Massive traffic spike from many IPs or to one target
        """
        logger.info(f"Generating {n_logs} DDoS logs...")
        
        logs = []
        start_time = datetime(2024, 6, 1, 0, 0, 0)
        target_ip = random.choice(self.external_ips)
        attacker_ips = random.sample(self.internal_ips, k=10)  # Multiple attackers
        
        for i in range(n_logs):
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400*30))
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source_ip': random.choice(attacker_ips),
                'dest_ip': target_ip,
                'source_port': random.randint(49152, 65535),
                'dest_port': 80,  # Usually HTTP
                'protocol': 'TCP',
                'bytes_sent': np.random.gamma(shape=5, scale=10000),  # LARGE! (DDoS)
                'bytes_received': 0,
                'packet_count': 1000,  # MANY! (DDoS)
                'duration_seconds': 0.5,
                'flags': 'SYN',
                'is_encrypted': False,
                'label': 'ddos'
            }
            logs.append(log)
        
        return pd.DataFrame(logs)
    
    def generate_data_exfiltration_logs(self, n_logs):
        """
        Generate data exfiltration attack logs.
        
        Pattern: Large outbound transfer from internal to external IP
        """
        logger.info(f"Generating {n_logs} data exfiltration logs...")
        
        logs = []
        start_time = datetime(2024, 6, 1, 0, 0, 0)
        compromised_ip = random.choice(self.internal_ips)
        attacker_external = random.choice([f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(50)])
        
        for i in range(n_logs):
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400*30))
            
            log = {
                'timestamp': timestamp.isoformat(),
                'source_ip': compromised_ip,
                'dest_ip': attacker_external,
                'source_port': random.randint(49152, 65535),
                'dest_port': random.choice([443, 80, 22]),
                'protocol': 'TCP',
                'bytes_sent': np.random.gamma(shape=10, scale=100000),  # HUGE outbound! (exfil)
                'bytes_received': np.random.gamma(shape=2, scale=1000),
                'packet_count': np.random.randint(100, 1000),
                'duration_seconds': np.random.exponential(scale=30),
                'flags': 'ACK',
                'is_encrypted': False,  # Attacker doesn't encrypt
                'label': 'data_exfiltration'
            }
            logs.append(log)
        
        return pd.DataFrame(logs)
    
    def generate_all_logs(self):
        """
        Generate complete dataset with normal + attack logs.
        
        FIXED: Now generates more balanced data for better model training
        - 6000 normal (60%)
        - 4000 attacks (40%) ← INCREASED from 5%!
          - 1500 port_scan
          - 1250 ddos
          - 1250 data_exfiltration
        
        Returns:
            DataFrame with all logs
        """
        logger.info(f"Generating {self.n_records} total logs...")
        
        # ========== FIXED: More balanced distribution ==========
        # Original: 95% normal, 5% attack (only 500 attacks!)
        # New: 60% normal, 40% attack (4000 attacks!)
        # This gives models enough examples to learn attack patterns
        
        normal_count = int(self.n_records * 0.60)  # 60% normal (was 95%)
        attack_count = self.n_records - normal_count  # 40% attacks (was 5%)
        
        logger.info(f"Distribution: {normal_count} normal, {attack_count} attacks")
        
        # Generate each attack type (distribute attacks equally)
        normal = self.generate_normal_logs(normal_count)
        
        port_scan_count = int(attack_count * 0.375)  # 37.5% of attacks
        ddos_count = int(attack_count * 0.3125)      # 31.25% of attacks
        exfil_count = attack_count - port_scan_count - ddos_count  # Remainder
        
        port_scans = self.generate_port_scanning_logs(port_scan_count)
        ddos = self.generate_ddos_logs(ddos_count)
        exfil = self.generate_data_exfiltration_logs(exfil_count)
        
        # Combine all
        all_logs = pd.concat([normal, port_scans, ddos, exfil], ignore_index=True)
        
        # Shuffle (so attacks aren't all at end)
        all_logs = all_logs.sample(frac=1).reset_index(drop=True)
        
        logger.info(f"Total logs generated: {len(all_logs)}")
        logger.info(f"\nLabel distribution:")
        logger.info(all_logs['label'].value_counts())
        
        return all_logs


def main():
    """Main function - generate and save logs."""
    logger.info("Starting network log generation...")
    logger.info("FIXED: Now generating MORE balanced data (60% normal, 40% attack)")
    
    # Generate logs (FIXED distribution!)
    generator = NetworkLogGenerator(n_records=10000)
    logs_df = generator.generate_all_logs()
    
    # Save to CSV
    output_path = "data/sample_logs/network_logs.csv"
    logs_df.to_csv(output_path, index=False)
    logger.info(f"✓ Logs saved to: {output_path}")
    
    # Show statistics
    logger.info("\n" + "="*80)
    logger.info("DATASET STATISTICS")
    logger.info("="*80)
    logger.info(f"Total records: {len(logs_df)}")
    logger.info(f"\nLabel distribution:")
    logger.info(logs_df['label'].value_counts())
    logger.info(f"\nPercentages:")
    logger.info(logs_df['label'].value_counts(normalize=True) * 100)
    
    logger.info(f"\n--- Feature Statistics ---")
    logger.info(f"Bytes sent (mean): {logs_df['bytes_sent'].mean():.2f}")
    logger.info(f"Bytes sent (std): {logs_df['bytes_sent'].std():.2f}")
    logger.info(f"\nBytes received (mean): {logs_df['bytes_received'].mean():.2f}")
    logger.info(f"Bytes received (std): {logs_df['bytes_received'].std():.2f}")
    logger.info(f"\nPacket count (mean): {logs_df['packet_count'].mean():.2f}")
    logger.info(f"Packet count (std): {logs_df['packet_count'].std():.2f}")


if __name__ == "__main__":
    main()