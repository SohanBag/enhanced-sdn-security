# -*- coding: utf-8 -*-
"""
NAS-DNN real-time DDoS detection in POX
---------------------------------------
- Extracts per-flow features similar to your training set
- Loads StandardScaler (pickle) and FULL PyTorch model (torch.save(model,...))
- Classifies each flow on PacketIn; installs DROP rule for attacks, L2-forward for benign
- Logs results with inference latency to ddos_packet_log.csv

Tested with POX "gar" / "dart" style APIs (OpenFlow 1.0).
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpid_to_str
from collections import defaultdict, deque
import time, os, csv, pickle, math
import threading

# ---- Optional heavy deps (OK to install in same venv as POX) ----
import numpy as np

# PyTorch (used exactly as you asked: load full model)
try:
  import torch
  TORCH_AVAILABLE = True
except Exception:
  TORCH_AVAILABLE = False

log = core.getLogger()


# =========================
# Configuration
# =========================
MODEL_PATH = os.environ.get("NAS_MODEL_PATH", "nas_best_512x3_full.pt")  # your .pt (full model)
SCALER_PATH = os.environ.get("SCALER_PATH", "standard_scaler.pkl")
LOG_CSV = os.environ.get("NAS_LOG", "ddos_packet_log.csv")

# Flow idle timeout (seconds)
BENIGN_IDLE = 30
ATTACK_IDLE = 120

# If probability >= this -> attack
ATTACK_THRESHOLD = 0.5

# Max history per flow for IAT stats
MAX_PKTS_KEEP = 256

# =========================
# Feature order (must match your training)
# =========================
FEATURE_ORDER = [
 'Fwd IAT Min','Fwd Packet Length Std','URG Flag Count','Flow IAT Min',
 'Bwd Packet Length Min','Init Bwd Win Bytes','Fwd Seg Size Min','Total Fwd Packets',
 'Subflow Fwd Packets','Protocol','Init Fwd Win Bytes','Avg Bwd Segment Size',
 'Bwd Packets Length Total','Bwd Packet Length Mean','Bwd Packet Length Max',
 'Subflow Bwd Bytes','Fwd Act Data Packets','Down/Up Ratio','Fwd Header Length',
 'Packet Length Std','Packet Length Variance','Fwd IAT Std','Bwd IAT Min',
 'Bwd IAT Mean','Bwd IAT Total','Bwd IAT Max','Fwd IAT Total','Flow Duration',
 'Fwd IAT Mean','Fwd IAT Max','Bwd Header Length','Subflow Bwd Packets',
 'Total Backward Packets','Flow IAT Max','Flow IAT Std','Bwd Packets/s',
 'Flow Packets/s','Fwd Packets/s','Flow IAT Mean','Flow Bytes/s',
 'Fwd Packets Length Total','Subflow Fwd Bytes','Fwd Packet Length Max',
 'Avg Packet Size','Packet Length Max','Packet Length Mean',
 'Fwd Packet Length Mean','Avg Fwd Segment Size','Fwd Packet Length Min',
 'Packet Length Min'
]

NUM_FEATURES = len(FEATURE_ORDER)


# =========================
# Utilities
# =========================
def now_ms():
  return int(time.time() * 1000)

def ensure_csv_header(path, header):
  exists = os.path.exists(path)
  f = open(path, 'ab' if exists else 'wb')
  with f:
    w = csv.writer(f)
    if not exists:
      w.writerow(header)

def safe_get(d, k, default=0.0):
  v = d.get(k, default)
  if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
    return default
  return v


# =========================
# Flow state + feature extractor
# =========================
class FlowStats(object):
  """
  Maintains per-flow counters needed for features.
  Keyed by 5-tuple: (srcIP, dstIP, srcPort, dstPort, proto)
  """
  __slots__ = (
    'first_ts','last_ts',
    'fwd_pkts','bwd_pkts','fwd_bytes','bwd_bytes',
    'fwd_len_list','bwd_len_list',
    'fwd_iat','bwd_iat','flow_iat',
    'fwd_seg_min','fwd_header_len','bwd_header_len',
    'urg_count','protocol','init_fwd_win','init_bwd_win',
    'fwd_act_data_pkts'
  )
  def __init__(self, proto):
    t = time.time()
    self.first_ts = t; self.last_ts = t
    self.fwd_pkts = 0; self.bwd_pkts = 0
    self.fwd_bytes = 0; self.bwd_bytes = 0
    self.fwd_len_list = deque(maxlen=MAX_PKTS_KEEP)
    self.bwd_len_list = deque(maxlen=MAX_PKTS_KEEP)
    self.fwd_iat = deque(maxlen=MAX_PKTS_KEEP)
    self.bwd_iat = deque(maxlen=MAX_PKTS_KEEP)
    self.flow_iat = deque(maxlen=MAX_PKTS_KEEP)
    self.fwd_seg_min = None
    self.fwd_header_len = 0
    self.bwd_header_len = 0
    self.urg_count = 0
    self.protocol = proto
    self.init_fwd_win = 0
    self.init_bwd_win = 0
    self.fwd_act_data_pkts = 0

  def update_dir(self, direction, length, header_len=0, flags=None, win_bytes=None):
    # direction: 'fwd' or 'bwd'
    now = time.time()
    iat_flow = now - self.last_ts
    self.flow_iat.append(iat_flow)
    self.last_ts = now

    if direction == 'fwd':
      self.fwd_pkts += 1
      self.fwd_bytes += length
      self.fwd_len_list.append(length)
      if len(self.fwd_iat) == 0:
        self.fwd_iat.append(0.0)
      else:
        self.fwd_iat.append(now - (self.last_ts - iat_flow))
      self.fwd_header_len += header_len
      if flags is not None and getattr(flags, 'urg', 0):
        self.urg_count += 1
      if self.fwd_seg_min is None:
        self.fwd_seg_min = length
      else:
        self.fwd_seg_min = min(self.fwd_seg_min, length)
      if win_bytes is not None and self.init_fwd_win == 0:
        self.init_fwd_win = win_bytes
      if length > 0:
        self.fwd_act_data_pkts += 1
    else:
      self.bwd_pkts += 1
      self.bwd_bytes += length
      self.bwd_len_list.append(length)
      if len(self.bwd_iat) == 0:
        self.bwd_iat.append(0.0)
      else:
        self.bwd_iat.append(now - (self.last_ts - iat_flow))
      self.bwd_header_len += header_len
      if win_bytes is not None and self.init_bwd_win == 0:
        self.init_bwd_win = win_bytes

  def duration(self):
    return max(1e-6, self.last_ts - self.first_ts)

  # ---- Helpers for stats
  @staticmethod
  def _np_stats(arr):
    if len(arr) == 0:
      return (0.0, 0.0, 0.0, 0.0)
    a = np.array(arr, dtype=np.float64)
    return (float(np.min(a)), float(np.mean(a)), float(np.max(a)), float(np.std(a)))

  def to_feature_vector(self):
    # Build a dict for clarity, then map to FEATURE_ORDER
    dur = self.duration()
    total_pkts = self.fwd_pkts + self.bwd_pkts
    total_bytes = self.fwd_bytes + self.bwd_bytes

    fwd_min, fwd_mean, fwd_max, fwd_std = self._np_stats(self.fwd_iat)
    bwd_min, bwd_mean, bwd_max, bwd_std = self._np_stats(self.bwd_iat)
    flow_min, flow_mean, flow_max, flow_std = self._np_stats(self.flow_iat)

    pkt_lengths = list(self.fwd_len_list) + list(self.bwd_len_list)
    pl_min, pl_mean, pl_max, pl_std = self._np_stats(pkt_lengths)
    pl_var = pl_std ** 2

    fwd_pl_min, fwd_pl_mean, fwd_pl_max, fwd_pl_std = self._np_stats(self.fwd_len_list)
    bwd_pl_min, bwd_pl_mean, bwd_pl_max, bwd_pl_std = self._np_stats(self.bwd_len_list)

    features = {
      'Fwd IAT Min': fwd_min,
      'Fwd Packet Length Std': fwd_pl_std,
      'URG Flag Count': float(self.urg_count),
      'Flow IAT Min': flow_min,
      'Bwd Packet Length Min': bwd_pl_min,
      'Init Bwd Win Bytes': float(self.init_bwd_win),
      'Fwd Seg Size Min': float(self.fwd_seg_min or 0.0),
      'Total Fwd Packets': float(self.fwd_pkts),
      'Subflow Fwd Packets': float(self.fwd_pkts),      # proxy
      'Protocol': float(self.protocol),
      'Init Fwd Win Bytes': float(self.init_fwd_win),
      'Avg Bwd Segment Size': (bwd_pl_mean if self.bwd_pkts else 0.0),
      'Bwd Packets Length Total': float(self.bwd_bytes),
      'Bwd Packet Length Mean': (bwd_pl_mean if self.bwd_pkts else 0.0),
      'Bwd Packet Length Max': bwd_pl_max,
      'Subflow Bwd Bytes': float(self.bwd_bytes),       # proxy
      'Fwd Act Data Packets': float(self.fwd_act_data_pkts),
      'Down/Up Ratio': float((self.bwd_pkts+1.0)/(self.fwd_pkts+1.0)),
      'Fwd Header Length': float(self.fwd_header_len),
      'Packet Length Std': pl_std,
      'Packet Length Variance': pl_var,
      'Fwd IAT Std': fwd_std,
      'Bwd IAT Min': bwd_min,
      'Bwd IAT Mean': bwd_mean,
      'Bwd IAT Total': float(sum(self.bwd_iat) if len(self.bwd_iat) else 0.0),
      'Bwd IAT Max': bwd_max,
      'Fwd IAT Total': float(sum(self.fwd_iat) if len(self.fwd_iat) else 0.0),
      'Flow Duration': dur,
      'Fwd IAT Mean': fwd_mean,
      'Fwd IAT Max': fwd_max,
      'Bwd Header Length': float(self.bwd_header_len),
      'Subflow Bwd Packets': float(self.bwd_pkts),
      'Total Backward Packets': float(self.bwd_pkts),
      'Flow IAT Max': flow_max,
      'Flow IAT Std': flow_std,
      'Bwd Packets/s': float(self.bwd_pkts)/dur,
      'Flow Packets/s': float(total_pkts)/dur,
      'Fwd Packets/s': float(self.fwd_pkts)/dur,
      'Flow IAT Mean': flow_mean,
      'Flow Bytes/s': float(total_bytes)/dur,
      'Fwd Packets Length Total': float(self.fwd_bytes),
      'Subflow Fwd Bytes': float(self.fwd_bytes),
      'Fwd Packet Length Max': fwd_pl_max,
      'Avg Packet Size': (float(total_bytes)/total_pkts) if total_pkts else 0.0,
      'Packet Length Max': pl_max,
      'Packet Length Mean': pl_mean,
      'Fwd Packet Length Mean': fwd_pl_mean,
      'Avg Fwd Segment Size': (fwd_pl_mean if self.fwd_pkts else 0.0),
      'Fwd Packet Length Min': fwd_pl_min,
      'Packet Length Min': pl_min
    }

    # Ordered vector
    vec = [safe_get(features, k, 0.0) for k in FEATURE_ORDER]
    return np.array(vec, dtype=np.float64)


# =========================
# Predictor wrapper (scaler + torch model)
# =========================
class Predictor(object):
  def __init__(self, scaler_path, model_path):
    self.scaler = None
    self.model = None
    self.device = "cpu"

    # Load scaler
    with open(scaler_path, "rb") as f:
      self.scaler = pickle.load(f)

    # Load model (full object)
    if not TORCH_AVAILABLE:
      raise RuntimeError("PyTorch not available in this environment")
    try:
      self.model = torch.load(model_path, map_location=self.device)
    except Exception as e:
      # If it's a TorchScript model, try jit.load
      try:
        self.model = torch.jit.load(model_path, map_location=self.device)
      except Exception as e2:
        raise RuntimeError("Failed to load model: %s / %s" % (str(e), str(e2)))
    self.model.eval()

    # If model expects specific dtype/shape, handle in predict()

  def predict_attack_prob(self, x_vec):
    """
    x_vec: numpy array (NUM_FEATURES,)
    returns: prob_attack (float 0..1)
    """
    # Scale
    x_scaled = self.scaler.transform(x_vec.reshape(1, -1))
    with torch.no_grad():
      xt = torch.from_numpy(x_scaled).float()
      out = self.model(xt)
      # Handle model outputs: could be logits or probabilities
      if out.shape[-1] == 1:
        # Binary logit -> sigmoid
        prob_attack = torch.sigmoid(out.squeeze()).item()
      else:
        # Softmax on last dim; assume index 1 = attack
        prob_attack = torch.softmax(out, dim=1)[0, 1].item()
    return float(prob_attack)


# =========================
# Simple L2 learning (for benign traffic)
# =========================
class L2Table(object):
  def __init__(self):
    self.mac_to_port = {}

  def learn(self, dpid, src, in_port):
    self.mac_to_port.setdefault(dpid, {})
    self.mac_to_port[dpid][src] = in_port

  def get_out_port(self, dpid, dst):
    t = self.mac_to_port.get(dpid, {})
    return t.get(dst, of.OFPP_FLOOD)


# =========================
# Main POX app
# =========================
class NASDDoSController(object):
  def __init__(self, connection):
    self.connection = connection
    self.dpid = connection.dpid
    self.l2 = L2Table()
    self.flow_state = {}  # key -> FlowStats
    self.predictor = None

    # Load model+scaler once per switch (thread to avoid blocking)
    def _load():
      try:
        self.predictor = Predictor(SCALER_PATH, MODEL_PATH)
        log.info("Model loaded for %s", dpid_to_str(self.dpid))
      except Exception as e:
        log.error("Model load failed: %s", e)
        self.predictor = None
    threading.Thread(target=_load).start()

    # CSV header
    ensure_csv_header(LOG_CSV, [
      "ts_ms","dpid","src","dst","sport","dport","proto","prob_attack",
      "label","latency_ms"
    ])

    connection.addListeners(self)

  # --- Helpers
  @staticmethod
  def _five_tuple(packet):
    ip = packet.find('ipv4')
    if not ip:
      return None
    proto = ip.protocol
    src = str(ip.srcip); dst = str(ip.dstip)
    sport = dport = 0
    l4 = ip.find('tcp') or ip.find('udp')
    if l4:
      sport = int(l4.srcport); dport = int(l4.dstport)
    return (src, dst, sport, dport, int(proto)), ip, l4

  def _flow_key_reverse(self, key):
    src, dst, sp, dp, pr = key
    return (dst, src, dp, sp, pr)

  def _get_state(self, key, proto):
    st = self.flow_state.get(key)
    if st is None:
      st = FlowStats(proto)
      self.flow_state[key] = st
    return st

  def _install_drop(self, event, match, idle=ATTACK_IDLE):
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.idle_timeout = idle
    fm.hard_timeout = 0
    # no actions => drop
    event.connection.send(fm)

  def _install_forward(self, event, match, out_port, idle=BENIGN_IDLE):
    fm = of.ofp_flow_mod()
    fm.match = match
    fm.idle_timeout = idle
    fm.hard_timeout = 0
    fm.actions.append(of.ofp_action_output(port = out_port))
    event.connection.send(fm)

  # --- PacketIn handler
  def _handle_PacketIn(self, event):
    packet = event.parsed
    dpid = self.dpid
    in_port = event.port

    # L2 learn
    self.l2.learn(dpid, packet.src, in_port)

    # Only IP traffic is classified; others flood like a switch
    res = self._five_tuple(packet)
    if res is None:
      outp = self.l2.get_out_port(dpid, packet.dst)
      msg = of.ofp_packet_out(data=event.ofp)
      msg.actions.append(of.ofp_action_output(port = outp))
      self.connection.send(msg)
      return

    key, ip, l4 = res
    rev_key = self._flow_key_reverse(key)

    # Determine direction (fwd if this exact key exists or new; bwd if reverse exists)
    direction = 'fwd'
    base = self.flow_state.get(key)
    if base is None and rev_key in self.flow_state:
      direction = 'bwd'
      base = self.flow_state[rev_key]
    if base is None:
      base = self._get_state(key, ip.protocol)

    # Lengths/header/flags
    payload_len = ip.payload_len
    header_len = ip.hl * 4  # IPv4 header length bytes

    flags = None; win_bytes = None
    if l4 and l4.__class__.__name__ == 'tcp':
      flags = l4
      win_bytes = getattr(l4, 'win', None)

    base.update_dir(direction, payload_len, header_len, flags, win_bytes)

    # Build features and classify occasionally (e.g., once we have a few packets)
    start_ms = now_ms()
    classify = (base.fwd_pkts + base.bwd_pkts) >= 4  # small warmup
    if not classify or self.predictor is None:
      # Forward like switch while warming up / model loading
      outp = self.l2.get_out_port(dpid, packet.dst)
      po = of.ofp_packet_out(data=event.ofp)
      po.actions.append(of.ofp_action_output(port = outp))
      self.connection.send(po)
      return

    vec = base.to_feature_vector()
    try:
      prob_attack = self.predictor.predict_attack_prob(vec)
    except Exception as e:
      log.error("Prediction error: %s", e)
      prob_attack = 0.0

    label = 1 if prob_attack >= ATTACK_THRESHOLD else 0
    latency = now_ms() - start_ms

    # ---- Logging
    try:
      with open(LOG_CSV, "ab") as f:
        w = csv.writer(f)
        w.writerow([
          now_ms(), dpid_to_str(dpid),
          "%s" % key[0], "%s" % key[1], key[2], key[3], key[4],
          round(prob_attack, 6), label, latency
        ])
    except Exception as e:
      log.warn("CSV log failed: %s", e)

    # ---- Install rule
    m = of.ofp_match.from_packet(packet, in_port)
    if label == 1:
      # DROP
      self._install_drop(event, m, idle=ATTACK_IDLE)
    else:
      # NORMAL FORWARD
      outp = self.l2.get_out_port(dpid, packet.dst)
      if outp == of.OFPP_FLOOD:
        # send only this packet while learning
        po = of.ofp_packet_out(data=event.ofp)
        po.actions.append(of.ofp_action_output(port = outp))
        self.connection.send(po)
      else:
        self._install_forward(event, m, outp, idle=BENIGN_IDLE)


# =========================
# POX launch
# =========================
class NASDDoSComponent(object):
  def __init__(self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self, event):
    log.info("Switch %s has connected", dpid_to_str(event.dpid))
    NASDDoSController(event.connection)

def launch():
  """
  pox.py log.level --DEBUG openflow.of_01 --port=6633 nas_ddos_controller
  Env vars:
    NAS_MODEL_PATH=/path/to/nas_best_512x3_full.pt
    SCALER_PATH=/path/to/standard_scaler.pkl
    NAS_LOG=/path/to/ddos_packet_log.csv
  """
  core.registerNew(NASDDoSComponent)
  log.info("NAS-DNN DDoS POX app loaded")
