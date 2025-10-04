from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
cache = {".net": "1.1.1.1", ".com": "2.2.2.2", ".io": "3.3.3.3", ".edu": "4.4.4.4"}

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  print("DNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """
  
  header = DNSHeader.parse(buff)
  print("DNS header", repr(header))
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    print(f"Question-{k} {repr(q)}")
    
  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    print(f"Answer-{k} {repr(a)}")
    if a.rtype == QTYPE.A:
      print("IP address")
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    print(f"Authority-{k} {repr(auth)}")
      
  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")

def read_command(command):
  
  # exit program
  if command == ".exit":
      exit()
  
  # list cache entries
  elif command == ".list":
    i = 1
    for key in cache.keys():
      print(f"{i}: {key} --> {cache[key]}")
      i+=1
  
  # clear cache
  elif command == ".clear":
    cache.clear()
  
  # remove entry n from cache
  elif command.split()[0] == ".remove":
    n = int(command.split()[1])
    if not 0 < n <= len(cache):
      print("Unable to read remove value")
      return
    i = 1
    for key in cache.keys():
      if i == n:
        cache.pop(key)
        break
      i+=1
  
if __name__ == '__main__':
  """ # Create a UDP socket
  sock = socket(AF_INET, SOCK_DGRAM)
  # Get all the .edu name servers from the ROOT SERVER
  get_dns_record(sock, "edu", ROOT_SERVER, "NS")
  
  # The following function calls are FAILED attempts to use Google Public DNS
  # (1) to get name servers which manages gvsu.edu
  # (2) to resolve the IP address of www.gvsu.edu
  get_dns_record(sock, "gvsu.edu", "8.8.8.8", "NS")      # (1)
  get_dns_record(sock, "www.gvsu.edu", "8.8.8.8", "A")   # (2)
  
  sock.close() """

  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  while True:
    domain_name = input("Enter a domain name or .exit > ")

    if domain_name[0] == '.':
      read_command(domain_name)
      continue

      # resolve given address name
      while True:
        
        get_dns_record(sock, domain_name, ROOT_SERVER, "NS")
        break
        # Use the function get_dns_record(____) (from the starter code
        # below) to resolve the IP address of the domain name in question
  
  sock.close()
