from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
from sklearn.ensemble import IsolationForest
import numpy as np
import logging
import json
from datetime import datetime

class PacketCapture:
    def __init__(self):
        '''
        The init method initialized the class by creating a
        queue.Queue to store captured packets and a threading
        event to control when the packet capture should stop.
        '''
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        '''
        THe packet_callback method acts as a handler for each captured
        packet and checks if the packet contains both IP and TCP layers.
        If so, it adds it to the queue for further processing.
        '''
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
        
    def start_capture(self, interface="eth0"):
        '''
        The start_capture method begins capturing packets on a specified
        interface (defaulting to eth0 to capture packets from the Ethernet interface).
        Run ifconfig to understand the available interfaces and select the appropriate interface from the list.
        '''
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store = 0,
                  stop_filter = lambda _: self.stop_capture.is_set())
        
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
    
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

'''Tracking connection flows and calculate statistics for packets in real time.
'''
class TrafficAnalyzer:
    
    '''__init__ method initializes two attributes: connections, which stores lists of related packets for each flow,
    and flow_stats, which stores aggregated statistics for each flow, such as packet count, byte count, start time,
    and the time of the most recent packet.
    '''
    def __init__(self):
        '''Using the defaultdict data structure in Python to 
        manage connections and flow statistics by organizing data by unique flows.
        '''
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count':0,
            'byte_count' : 0,
            'start_time' : None,
            'last_time' : None
        })

    def analyze_packet(self, packet):
        '''
        This class processes each packet. If the packet contains IP and TCP layers,
        it extracts the source and destination IPs and ports, forming an unique,
        flow_key to identify the flow. It updates the statistics for the flow by incrementing
        the packet count, adding the packet's size to the byte count, and setting or updating the start
        and last time of the flow. Eventually, it calls extract_features to calculate and return additional metrics.
        '''
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            #Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)
        
    def extract_features(self, packet, stats):
        '''
        This class computes detailed characteristics of the flow and the current packet.
        These include the packet size, flow duration, packet rate, byte rate, TCP flags,
        and the TCP window size. These metrics are quite useful to identify patterns, anomalies, or potential threats in network traffic.
        '''
        duration = stats['last_time'] - stats['start_time']
        if duration == 0:
            duration = 1e-6  # Avoid division by zero
        return{
            'packet_size' : len(packet),
            'flow_duration' : stats['last_time'] - stats['start_time'],
            'packet_rate' : stats['packet_count'] / duration,
            'byte_rate' : stats['byte_count'] / duration,
            'tcp_flags' : packet[TCP].flags,
            'window_size' : packet[TCP].window
        }

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination = 0.1,
            random_state = 42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data=[]
    
    def load_signature_rules(self):
        return{
            'syn_flood' : {
                'condition' : lambda features: (
                    features['tcp_flags'] == 2 and # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan' : {
                'condition' : lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
             }
        }
    
    '''
    The train_anomaly_detector method trains the Isolation Forest model using a dataset of normal traffic features.
    This enables the model to differentiate typical patterns from anomalies.
    '''
    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)
    
    '''
    The detect_threats method evaluates network traffic features for potential threats using two approaches:
    
    1. Signature-Based Detection: It iteratively goes through each of the pre-defined rules, applying the rule's
    condition to the traffic features. If a rule matches, a signature-based threat is recorded with high confidence.
    
    2. Anomaly-Based Detection: It processes the feature vector (packet size, packet rate, and byte rate) through the Isolation
    Forest model to calculate an anomaly score. If the score indicates unusual behavior, the detection engine triggers it as an 
    anomaly and produces a confidence score proportional to the anomaly's severity.
    '''
    def detect_threats(self, features):
        threats = []

        #Signature based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type' : 'signature',
                    'rule' : rule_name,
                    'confidence' : 1.0
                })
        
        #Anomaly-based detection
        if hasattr(self.anomaly_detector, "estimator_"):
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate']
            ]])

            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.55: #Threshold for anomaly detection
                threats.append({
                    'type' : 'anomaly',
                    'score' : anomaly_score,
                    'confidence' : min(1.0, abs(anomaly_score))
                })
            
        else:
            print("Warning: Anomaly detector is not trained. Skipping anomaly detection.")
        
        '''
        Finally, returning the aggregated list of identified threats with their respective annotation (either signature or anomaly),
        the rule or score that triggered the anomaly, and a confidence score that suggests how likely it is that the identified pattern
        is a threat.
        '''
        return threats

class AlertSystem:
    '''
    The init method sets up a logger named IDS_Alerts with an INFO logging level to capture
    aler information. It is writing logs to 'ids_alerts.log' by default. 
    '''
    def __init__ (self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    '''
    The generate_alert method is responsible for creating structured alert entries. Each alert
    includes key information such as the timestamp of detection, the type of threat, the source and destination IPs
    involved, the confidence level of the detection, and additional threat-specific details. These alerts are logged as WARNING 
    level messaves in JSON format.
    '''
    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp' : datetime.now().isoformat(),
            'threat_type' : threat['type'],
            'source_ip' : packet_info.get('source_ip'),
            'destination_ip' : packet_info.get('destination_ip'),
            'confidence' : threat.get('confidence', 0.0),
            'details' : threat
        }

        self.logger.warning(json.dumps(alert))

        '''
        If confidence level of a detected threat is higher than 0.8, the alert is escalated and logged as a CRITICAL
        level message. 
        '''
        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # Implement additional notification methods here
            # (e.g., email, Slack, SIEM integration)


class IntrusionDetectionSystem:
    def __init__(self, interface = "eth0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        user_interface = input(f"Enter network interface (default is 'eth0'): ").strip()
        self.interface = user_interface if user_interface else interface
    
    def collect_normal_traffic(self, sample_count = 50):
        print(f"Collecting {sample_count} normal traffic samples for training...")
        collected_samples = []

        while len(collected_samples) < sample_count:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=2)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    print(features) #This print statement is to check if the program is getting data or not
                    collected_samples.append([
                        features['packet_size'],
                        features['packet_rate'],
                        features['byte_rate']
                    ])
            except queue.Empty:
                continue
        
        if collected_samples:
            self.detection_engine.train_anomaly_detector(np.array(collected_samples))
            print("Training completed.")
        
        else:
            print("Warning: No training data collected. Anomaly detection may not work.")

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)
        
        self.collect_normal_traffic()

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip' : packet[IP].src,
                            'destination_ip' : packet[IP].dst,
                            'source_port' : packet[TCP].sport,
                            'destination_port' : packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)
            
            except queue.Empty:
                continue

            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()