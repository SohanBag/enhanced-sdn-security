P4-SDN-NAS-DDoS-Detection

Hybrid SDN security framework combining P4 switch signature-based detection with an SDN controller–integrated NAS-optimized DNN (NAS-DNN) for real-time Distributed Denial of Service (DDoS) attack detection and mitigation.

Dataset Performance: Achieved ~99% accuracy on CICDDoS2019 dataset

Real-Time Validation: Detected attacks with high accuracy at latency < 50 ms

🚀 Features

Data Plane (P4 switch):

Detects and drops well-known volumetric attacks (SYN flood, DNS amplification) directly in the switch

Eliminates controller overhead for known signatures

Control Plane (SDN Controller with NAS-DNN):

Classifies remaining flows as benign or malicious

Uses Neural Architecture Search–optimized DNN for adaptability and efficiency

Runs inside POX controller with low CPU & memory usage

Real-Time Detection:

Replay of CICDDoS2019 traffic

<50 ms latency per classification

Logging to ddos_packet_log.csv for visualization

📂 Repository Structure
.
├── README.md              # Project documentation
├── REAL.ipynb             # Jupyter notebook with preprocessing and training pipeline
├── advanced_ddos.p4       # P4 program for signature-based detection
├── custom_p4_topo.py      # Mininet topology with P4 switch
├── pox.py                 # POX controller launcher
├── replay_csv_flows.py    # Script to replay dataset flows in real time
├── nas_best_512x3_full.pt # Trained NAS-DNN model (add to repo or provide link)
├── standard_scaler.pkl    # Preprocessing scaler for feature normalization

⚙️ Setup & Usage
1️⃣ Requirements

Python 3.8+

Mininet

BMv2 (Behavioral Model v2 for P4)

POX Controller

PyTorch, scikit-learn, pandas, numpy

2️⃣ Compile & Run P4 Program
p4c-bm2-ss advanced_ddos.p4 -o build/advanced_ddos.json

3️⃣ Launch Mininet Topology
sudo python3 custom_p4_topo.py

4️⃣ Start POX Controller with NAS-DNN
cd pox
PYTHONPATH=. \
NAS_MODEL_PATH=../nas_best_512x3_full.pt \
SCALER_PATH=../standard_scaler.pkl \
NAS_LOG=../ddos_packet_log.csv \
./pox.py log.level --INFO openflow.of_01 --port=6633 nas_ddos_controller

5️⃣ Replay Traffic for Real-Time Detection
python3 replay_csv_flows.py

📊 Results

Signature Detection (P4 switch):

SYN flood & DNS amplification dropped at line rate

95–98% drop rate under mixed traffic conditions

NAS-DNN Detection (POX controller):

~99% accuracy, precision, recall, F1-score on CICDDoS2019 dataset

Real-time detection with <50 ms latency

Efficient CPU & memory usage for scalable deployment

📖 References

This implementation is based on the Master's Thesis:
"Enhanced Software-Defined Network Security through P4-Switch Integrated Signature-Based Approach and NAS-Enhanced Deep Neural Networks"
by Sohan Bag, NTUST (2025)

