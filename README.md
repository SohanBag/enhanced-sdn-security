# P4-SDN-NAS-DDoS-Detection  

Hybrid SDN security framework combining a **P4 switch** (signature-based detection) with an **SDN controller–integrated NAS-optimized Deep Neural Network (NAS-DNN)** for real-time DDoS attack detection and mitigation.  

- **~99% Accuracy** on CICDDoS2019 dataset  
- **< 50 ms Latency** in real-time detection  
- **Dual-layer defense**: P4 switch (fast filtering) + NAS-DNN (adaptive learning)  

## Features  

### 🔹Data Plane (P4 Switch)  
- Detects & drops well-known volumetric attacks (SYN flood, DNS amplification)  
- Inline packet filtering at the switch → **low latency, zero controller overhead**  

### 🔹Control Plane (POX + NAS-DNN)  
- Classifies unknown/mixed flows as benign or malicious  
- NAS-optimized DNN (Optuna-tuned) for high accuracy & adaptability  
- Embedded inside POX controller for real-time inference with low resource usage  

### 🔹Real-Time Evaluation  
- Traffic replay from CICDDoS2019 dataset  
- Accurate detection with **< 50 ms latency**  
- Results logged in `ddos_packet_log.csv` for visualization  

## Project Structure  

- README.md # Project documentation
- REAL.ipynb # Preprocessing + NAS-DNN training pipeline
- advanced_ddos.p4 # P4 program (signature detection)
- ustom_p4_topo.py # Mininet topology with BMv2 switch
- pox.py # POX controller launcher
- nas_ddos_controller.py # NAS-DNN enabled POX app
- replay_csv_flows.py # Replay CICDDoS2019 flows
- nas_best_512x3_full.pt # Trained NAS-DNN model (PyTorch full object)
- standard_scaler.pkl # Preprocessing scaler for normalization


## Requirements  

- Python 3.8+  
- [Mininet](http://mininet.org/)  
- [BMv2](https://github.com/p4lang/behavioral-model) (P4 software switch)  
- [POX Controller](https://github.com/noxrepo/pox)  
- PyTorch, scikit-learn, pandas, numpy  


## Setup & Usage  

### 1️⃣ Compile P4 Program  
```bash
p4c-bm2-ss advanced_ddos.p4 -o build/advanced_ddos.json
