from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

SWITCH_BIN = "simple_switch"
P4_JSON = "advanced_ddos.json"
THRIFT_PORT = 9090

class P4Switch(OVSSwitch):
    def __init__(self, name, json_path=P4_JSON, thrift_port=THRIFT_PORT, **kwargs):
        super().__init__(name, **kwargs)
        self.json_path = json_path
        self.thrift_port = thrift_port

    def start(self, controllers):
        cmd = f"{SWITCH_BIN} --log-console --thrift-port {self.thrift_port} {self.json_path} "
        # Attach Mininet interfaces in order
        for idx, intf in enumerate(self.intfNames(), start=1):
            cmd += f"-i {idx}@{intf} "
        cmd += "&"
        print(f"*** Launching BMv2: {cmd}")
        self.cmd(cmd)
        super(P4Switch, self).start(controllers)

    def stop(self):
        self.cmd("pkill -9 simple_switch")
        super(P4Switch, self).stop()

def run():
    setLogLevel("info")
    net = Mininet(
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633),
        switch=P4Switch,
        link=TCLink,
        autoSetMacs=True
    )

    # Three hosts in the same /24 subnet
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    # Single P4 switch
    s1 = net.addSwitch("s1")

    # Connect hosts
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()
    print("*** Mininet + BMv2 is up. Drop to CLI with 'mininet>' prompt")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    run()
