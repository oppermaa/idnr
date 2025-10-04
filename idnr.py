from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
cache = dict()

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  print("DNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  
  # logic for socket timeout
  try:
    pkt, _ = udp_socket.recvfrom(8192)
  except udp_socket.timeout:
    return
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
    if header.rcode == RCODE.NXDOMAIN:
      return "Domain does not exist"
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
      # cache[a.rname] = a.rdata
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    print(f"Authority-{k} {repr(auth)}")
      
  # Parse the additional section #5
  domain_list = list()
  for k in range(header.ar):
    adr = RR.parse(buff)
    print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    
    # cache ips, append to return list
    if adr.rtype == QTYPE.A:
      cache[adr.rname] = adr.rdata
      domain_list.append(adr)
    
  return domain_list


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
  
  # unknown command
  else:
    print("Unable to read command")


def query(domain_name):

    # tokenize url by number of periods/dots
    path = [f"root server ({ROOT_SERVER})"]
    tokens = domain_name.split('.')
    name = tokens[-1]
      
    # for each extension to the domain, fetch list of domains to query next
    domain_list = get_dns_record(sock, name, ROOT_SERVER, "NS")
    
    # domain does not exist
    if domain_list == "Domain does not exist":
      path.append(domain_list)
      return path
    
    for i in range(len(tokens) - 2, -1, -1):
      name = tokens[i] + '.' + name

      # for each domain in domain_list, in case domains fail or timeout
      for domain in domain_list:
        return_value = get_dns_record(sock, name, str(domain.rdata), "NS")
        path.append(f"{domain.rname} ({domain.rdata})")
        if isinstance(return_value, list):
          domain_list = return_value
          break
        
        # domain does not exist
        elif return_value == "Domain does not exist":
          path.append(return_value)
          break

    return path


if __name__ == '__main__':

  # create UDP socket, set timeout
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  # user input loop
  while True:
    domain_name = input("Enter a domain name or .exit > ")

    # run commands
    if domain_name[0] == '.':
      read_command(domain_name)
      continue

    path = query(domain_name)
    print(f"\nFull Path for {domain_name}:")
    for step in path:
      print(step)
    print()
  
  sock.close()
