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
  pkt, _ = udp_socket.recvfrom(8192)
  '''if udp_socket.timeout:
    return "timeout"'''
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
  cache[domain] = list()
  print("DNS header", repr(header))
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    if header.rcode == RCODE.NXDOMAIN:
      cache[domain] = "Domain does not exist"
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
    
    # cache query, return
    if a.rtype == QTYPE.A or a.rtype == QTYPE.CNAME:
      cache[domain].append(a)
      return a
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    print(f"Authority-{k} {repr(auth)}")
      
  # Parse the additional section #5
  domain_list = list()
  for k in range(header.ar):
    adr = RR.parse(buff)
    print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    
    # cache query, append to return list, return
    if adr.rtype == QTYPE.A:
      cache[domain].append(adr)
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
      if isinstance(cache[key], list):
        print(f"{i}: {key} --> {len(cache[key])} result(s)")
      elif isinstance(cache[key], str):
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


# produces list of queries, eg. ["net", "gvsu.net", "www.gvsu.net"]
def order_queries(domain_name):
  tokens = domain_name.split('.')
  name = tokens[-1]
  queries = [name]
  for i in range(len(tokens) - 2, -1, -1):
    name = tokens[i] + '.' + name
    queries.append(name)
  
  return queries


def check_cache(domain_name, path):
  if domain_name in cache.keys():
    path.append(f"cache: queried for {domain_name}")
    return cache[domain_name]
  return None


def lookup(domain_name, path, cname=None):
  queries = order_queries(domain_name)
  domain_list = [ROOT_SERVER]
  return_value = list()

  for name in queries:
    
    # try each domain
    for domain in domain_list:

      # if first query, else
      if name == queries[0]:
        return_value = get_dns_record(sock, name, ROOT_SERVER, "NS")
        path.append(f"root server ({ROOT_SERVER}) <-- queried for {name}")
      else:
        return_value = get_dns_record(sock, name, str(domain.rdata), "A")
        path.append(f"{domain.rname} ({domain.rdata}) <-- queried for {name}")
      
      # if server couldn't find result, try next in list
      if not return_value:
        continue

      # if domain does not exist, stop iterating
      domain_list = return_value
      if domain_list == "Domain does not exist":
        return path, domain_list, cname

      # domain name is an alias
      if not isinstance(domain_list, (list, str)) and domain_list.rtype == QTYPE.CNAME:
        cname = domain_list.rdata
        return lookup(str(cname).strip('.'), path, str(cname))

      break

  return path, domain_list, cname


def print_summary(domain_name, path, domains, cname):
  print(f"\nFull Path for {domain_name}:")
  for step in path:
    print(step)
  print(f"\n{domain_name} IPv4(s):")
  if isinstance(domains, list):
    for domain in domains:
      print(f"{domain.rname}: {domain.rdata}")
  elif domains == "Domain does not exist":
    print("Domain does not exist")
  else:
    if cname:
      print(f"cname: {str(cname)}")
    print(f"{domains.rname}: {domains.rdata}")
  print()


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
     
    # check cache or query
    path, domain_list, cname = lookup(domain_name, [])

    # output summary
    print_summary(domain_name, path, domain_list, cname)
  
  sock.close()
