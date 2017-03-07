#!env python

"""
Simple script to scan subnets and print ssl signing algorithm
"""

import argparse
import M2Crypto
import nmap
import re
import socket
import ssl
import sys


parser = argparse.ArgumentParser()
parser.add_argument('-o', action='append', help="Host/Subnet to scan", default=['127.0.0.1'])
parser.add_argument('-p', action="append", help="TCP Ports to scan", default=['443','8443'])
args = parser.parse_args()

if len(args.o) > 1:
  h = args.o[1:]
else:
  h = args.o

if len(args.p) > 2:
  p = args.p[2:]
else:
  p = args.p

for entry in h:
  try:
    nm = nmap.PortScanner()
  except nmap.nmap.PortScannerError as e:
    print "Failed to initialize nmap\n%s" % e.value
    sys.exit(1)

  nms = nm.scan(entry, ",".join(p), arguments='')

  if nms:
    for host in nm.all_hosts():
      for port in nm[host].all_tcp():
        if nm[host]['tcp'][port]['state'] == 'open':
          try:
            cert = str(ssl.get_server_certificate((host, port)))
          except ssl.SSLError:
            print '%s:%d Error occurred during connection. Not an SSL enabled port?' % (host, port)
            continue
          except socket.error as serr:
            if serr.errno == socket.errno.ETIMEDOUT:
              print "%s:%d Connection timed out" % (host, port)
              continue
            elif serr.errno == 104:
              print "%s:%d Connection reset by peer" % (host, port)
              if len(cert) == 0:
                continue
              else:
                pass
            else:
              raise serr

          try:
            x509 = M2Crypto.X509.load_cert_string(cert)
          except M2Crypto.X509.X509Error:
            print "%s Could not load_cert_string" % host
            continue

          res = re.search("Signature\s+Algorithm:\s+(?P<sigal>.*)", x509.as_text())

          if res:
            print "%s:%d: %s" % (host, port, res.group('sigal'))
          else:
            print "%s:%d No valid signature algorithm found!" % (host, port)
