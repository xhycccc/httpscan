#!/usr/bin/env python
#coding:utf-8
# Author: Zeroh

import re
import sys
import Queue
import threading
import optparse
import requests
from IPy import IP

printLock = threading.Semaphore(1)  #lock Screen print
TimeOut = 5  #request timeout

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36','Connection':'close'}

class scan():

  def __init__(self,cidr,threads_num, ports):
    self.threads_num = threads_num
    self.cidr = IP(cidr)
    self.ports = ports
    #build ip queue
    self.IPs = Queue.Queue()
    for ip in self.cidr:
      ip = str(ip)
      for port in self.ports:
        self.IPs.put('%s:%d' % (ip, port))


  def request(self):
    with threading.Lock():
      while self.IPs.qsize() > 0:
        ip = self.IPs.get()

        try:
          r = requests.Session().get('http://'+str(ip),headers=header,timeout=TimeOut)
          status = r.status_code
          title = re.search(r'<title>(.*)</title>', r.text) #get the title
          if title:
            title = title.group(1).strip().strip("\r").strip("\n")[:30]
          else:
            title = "None"
          banner = ''
          try:
            banner += r.headers['Server'][:20] #get the server banner
          except:pass
          printLock.acquire()
          print "|%-21s|%-6s|%-20s|%-30s|" % (ip,status,banner,title)
          print "+---------------------+------+--------------------+------------------------------+"

          #Save log
          with open("./log/"+self.cidr.strNormal(3)+".log",'a') as f:
            f.write(ip+"\n")

        except Exception,e:
          printLock.acquire()
        finally:
          printLock.release()

  #Multi thread
  def run(self):
    for i in range(self.threads_num):
      t = threading.Thread(target=self.request)
      t.start()

if __name__ == "__main__":
  parser = optparse.OptionParser("Usage: %prog [options] target")
  parser.add_option("-t", "--thread", dest = "threads_num",
    default = 10, type = "int",
    help = "[optional]number of  theads,default=10")
  parser.add_option("-p", "--port", dest = "ports",
    default = "80", type = "str",
    help = "[optional]80,443 or 80-443, default 80")
  (options, args) = parser.parse_args()
  if len(args) < 1:
    parser.print_help()
    sys.exit(0)

  print "+---------------------+------+--------------------+------------------------------+"
  print "|          IP         |Status|       Server       |            Title             |"
  print "+---------------------+------+--------------------+------------------------------+"


  ports = []
  if ',' in options.ports:
    ports = [int(port) for port in options.ports.split(',')]
  elif '-' in options.ports:
    start, end = options.ports.split('-')
    ports = [port for port in range(int(start), int(end)+1)]
  else:
    ports.append(int(options.ports))

  s = scan(cidr=args[0],threads_num=options.threads_num, ports=ports)
  s.run()
