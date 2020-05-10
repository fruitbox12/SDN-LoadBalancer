# Copyright 2013,2014 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A very sloppy IP load balancer.

Run it with --ip=<Service IP> --servers=IP1,IP2,...

By default, it will do load balancing on the first switch that connects.  If
you want, you can add --dpid=<dpid> to specify a particular switch.

Please submit improvements. :)
"""

from pox.core import core
import pox
log = core.getLogger("iplb")

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str, str_to_dpid

import pox.openflow.libopenflow_01 as of

import time
import random

FLOW_IDLE_TIMEOUT = 5
FLOW_MEMORY_TIMEOUT = 60 * 5
UPDATE_DATA_FLOW = 12




class MemoryEntry (object):
  """
  Record for flows we are balancing

  Table entries in the switch "remember" flows for a period of time, but
  rather than set their expirations to some long value (potentially leading
  to lots of rules for dead connections), we let them expire from the
  switch relatively quickly and remember them here in the controller for
  longer.

  Another tactic would be to increase the timeouts on the switch and use
  the Nicira extension which can match packets with FIN set to remove them
  when the connection closes.
  """
  def __init__ (self, server, first_packet, client_port):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')

    return self.server,ipp.srcip,tcpp.dstport,tcpp.srcport


class iplb (object):
  """
  A simple IP load balancer

  Give it a service_ip and a list of server IP addresses.  New TCP flows
  to service_ip will be randomly redirected to one of the servers.

  We probe the servers to see if they're alive by sending them ARPs.
  """
  def __init__ (self, connection, service_ip, servers,method,weights,loadBalancerType):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.method = method
    self.con = connection
    self.mac = self.con.eth_addr
    self.weights = weights
    self.live_servers = {} # IP -> MAC,port
    self.loadBalancerType = loadBalancerType
    self.select_servers = []
    self.server_weights = {}
    

    for index,ip in enumerate(self.servers):
        self.server_weights[ip] = weights[index]

    if loadBalancerType == 2:
        self.select_servers = []
        for index,server in enumerate(self.servers):
          temp = []
          temp.append(server)
          self.select_servers = self.select_servers + temp * int(self.server_weights[server])
    else:
        self.select_servers = self.servers
          

    
    

    log.info('selected server list is {}'.format(self.select_servers))


          
    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log
    

    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = 5

    # How long do we wait for an ARP reply before we consider a server dead?
    self.arp_timeout = 3

    self.last_update = time.time()
    # Data transferred map (IP -> data transferred in the last 
    # UPDATE_DATA_FLOW seconds).
    self.data_flow = {}
    for server in self.servers:
      self.data_flow[server] = 0

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)

  def _do_expire (self):
    """
    Expire probes and "memorized" flows

    Each of these should only have a limited lifetime.
    """
    t = time.time()
    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]
          # del self.server_weights[ip]
          while ip in self.select_servers:
                self.select_servers.remove(ip)

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    r = max(.25, r) # Cap it at four per second
    return r

  def round_robin(self):
        choose_server = self.select_servers.pop(0)
        self.select_servers.append(choose_server)
        log.info('server choosen is {} using round_robin'.format(choose_server))
        return choose_server
       
  def random_selection(self):
        choose_server = random.choice(self.live_servers.keys())
        log.info('server choosen is {} using random method'.format(choose_server))
        return choose_server

  def least_connection(self):
        servers = self.servers
        weights = self.server_weights
        data_flow = self.data_flow      
        choose_server = self.servers[0]
        priorityValue = data_flow[choose_server] / int(weights[choose_server])
        for id in range(1,len(self.servers)):
              priorityValue2 = self.data_flow[servers[id]] / int(weights[servers[id]])
              if priorityValue > priorityValue2:
                    choose_server = servers[id]
        log.info('server choosen is {} using least connection method'.format(choose_server))
        return choose_server
              
              
        
        
        

  def _pick_server (self, key, inport):
    """
    Pick a server for a (hopefully) new connection
    """
    if self.loadBalancerType == 0:
          return self.random_selection()
    elif self.loadBalancerType == 3:
          return self.least_connection()
    else:
          return self.round_robin()

  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed
    #log.info('packet response {}'.format(packet))
    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.data_flow[arpp.protosrc] = 0
              # if arpp.protosrc not in self.weights.keys():
              #  self.weights[arpp.protosrc] = 1
              # tempServerList = []
              # tempServerList.append(arpp.protosrc)
              # self.select_servers += tempServerList
              self.log.info("Server %s up", arpp.protosrc)
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()
    # It's TCP.

    ipp = packet.find('ipv4')

    # Update the data count table, if needed.
    if time.time() - self.last_update > UPDATE_DATA_FLOW:
      for server in self.data_flow.keys():
        self.data_flow[server] = 0
      self.last_update = time.time()

    if ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client

      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.debug("No client for %s", key)
        return drop()

      # Refresh time timeout and reinstall.
      entry.refresh()

      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


    elif ipp.dstip == self.service_ip:
      # Ah, it's for our service IP and needs to be load balanced

      # Do we already know this flow?
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.memory.get(key)
      if entry is None or entry.server not in self.live_servers:
        # Don't know it (hopefully it's new!)
        if len(self.live_servers) == 0:
          self.log.warn("No servers!")
          return drop()

        # Pick a server for this flow
        server = self._pick_server(key, inport)
        self.log.debug('selected server is %s', server)
  
        # self.servers.append(server)
        self.log.debug('re-arranged server list is %s %s',server,self.select_servers)
        self.log.debug("Directing traffic to %s", server)
        entry = MemoryEntry(server, packet, inport)
        self.memory[entry.key1] = entry
        self.memory[entry.key2] = entry

      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


# Remember which DPID we're operating on (first one to connect)
_dpid = None


def launch (ip, servers, dpid = None,method='default',weights=[]):
  global _dpid
  if dpid is not None:
    _dpid = str_to_dpid(dpid)

  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
  ip = IPAddr(ip)
  weights_selected = []
  if weights and len(weights) > 0:
    weights_selected = weights.split(',')
  else:
    for i in servers:
          weights_selected.append(1)
  
  if len(weights_selected) is not len(servers):
        log.error('length of weights and servers are not equal')
        exit(1)

              

  loadBalancerType = 0
  if method == 'round_robin':
        loadBalancerType = 1
  elif method == 'weighted_round_robin':
        loadBalancerType = 2
  elif method == 'least_connection':
        loadBalancerType = 3
      
  # We only want to enable ARP Responder *only* on the load balancer switch,
  # so we do some disgusting hackery and then boot it up.
  from proto.arp_responder import ARPResponder
  old_pi = ARPResponder._handle_PacketIn
  def new_pi (self, event):
    if event.dpid == _dpid:
      # Yes, the packet-in is on the right switch
      return old_pi(self, event)
  ARPResponder._handle_PacketIn = new_pi

  # Hackery done.  Now start it.
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})
  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)


  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      _dpid = event.dpid
    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      if not core.hasComponent('iplb'):
        # Need to initialize first...
        # log.info('server_weights'.format(server_weights))
        core.registerNew(iplb, event.connection, IPAddr(ip),servers,method,weights_selected,loadBalancerType)
        log.info("IP Load Balancer Ready.")
      log.info("Load Balancing on %s", event.connection)

      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)
  
  def _handle_FlowStatsReceived (event):
    for f in event.stats:
      ip_dst = f.match.nw_dst
      ip_src = f.match.nw_src

      if ip_dst != None and IPAddr(ip_dst) in core.iplb.servers:
        core.iplb.data_flow[IPAddr(ip_dst)] += f.byte_count

      if ip_src != None and IPAddr(ip_src) in core.iplb.servers:
        core.iplb.data_flow[IPAddr(ip_src)] += f.byte_count

  core.openflow.addListenerByName("FlowStatsReceived", _handle_FlowStatsReceived)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

  from pox.lib.recoco import Timer

  def _timer_getStats ():
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  # Request flow stats every FLOW_IDLE_TIMEOUT second.
  Timer(FLOW_IDLE_TIMEOUT, _timer_getStats, recurring=True) 
