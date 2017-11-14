#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import nfqueue
from scapy.all import *
import os
import re

from os import path


#os.system('iptables -A OUTPUT -p tcp --dport 1337 -j NFQUEUE --queue-num 0')
os.system('iptables -A OUTPUT -p tcp --dport 1337 -d www.url.com -j NFQUEUE --queue-num 0')


my_rewrite = 'trigger1'

payload_redirect = [re.compile(re.escape(x.lower()), re.IGNORECASE) for x in [
  'triggera',
  'triggerb',
  
]]

logfile = open('log.txt', 'w', 0)

def callback(arg1,payload):
  data = payload.get_data()
  pkt = IP(data)

  payload_before = len(pkt[TCP].payload)

  payload_text = str(pkt[TCP].payload)
  for payload_redirect in addresses_to_redirect:
    payload_text = payload_redirect.sub(my_rewrite, payload_text)
  pkt[TCP].payload = payload_text

  payload_after = len(payload_text)

  payload_dif = payload_after - payload_before

  pkt[IP].len = pkt[IP].len + payload_dif

  pkt[IP].ttl = 40

  del pkt[IP].chksum
  del pkt[TCP].chksum
  payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
  logfile.write(payload_text)
  logfile.write('\n')
  logfile.flush()
def main():
  q = nfqueue.queue()
  q.open()
  q.bind(socket.AF_INET)
  q.set_callback(callback)
  q.create_queue(0)
  try:
    q.try_run() # Main loop
  except KeyboardInterrupt:
    q.unbind(socket.AF_INET)
    q.close()
    if path.exists('./restart_iptables'):
      os.system('./restart_iptables')

main()
