from mininet.topo import Topo

class Edge:
	def __init__(self, first, second):
		self.first = first
		self.second = second

class Topology(Topo):
	def __init__(self):
		Topo.__init__(self)

		switches = [
			self.addSwitch('s1'),
			self.addSwitch('s2'),
		]

		firewall = self.addSwitch('s3')

		server_hosts = [
			self.addHost('h101', ip='10.0.0.1/24', defaultRoute='via 10.0.0.1'),
			self.addHost('h102', ip='10.0.0.2/24', defaultRoute='via 10.0.0.2'),
			self.addHost('h103', ip='10.0.0.3/24', defaultRoute='via 10.0.0.3'),
		]

		user_hosts = [
			self.addHost('h201', ip='192.168.0.1/24', defaultRoute='via 192.168.0.1'),
			self.addHost('h202', ip='192.168.0.2/24', defaultRoute='via 192.168.0.2'),
			self.addHost('h203', ip='192.168.0.3/24', defaultRoute='via 192.168.0.3'),
			self.addHost('h204', ip='192.168.0.4/24', defaultRoute='via 192.168.0.4'),
		]

		edges = [
			Edge(switches[0], firewall),
			Edge(switches[1], firewall),

			Edge(server_hosts[0], switches[0]),
			Edge(server_hosts[1], switches[0]),
			Edge(server_hosts[2], switches[0]),

			Edge(user_hosts[0], switches[1]),
			Edge(user_hosts[1], switches[1]),
			Edge(user_hosts[2], switches[1]),
			Edge(user_hosts[3], switches[1]),
		]

		for edge in edges:
			self.addLink(edge.first, edge.second, bw=100)

topos = {
	'Topology': Topology,
}


