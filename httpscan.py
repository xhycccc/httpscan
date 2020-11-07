#!/usr/bin/env python
#coding:utf-8
# Author: Zeroh
import os
import re
import sys
import json
import Queue
import traceback
import threading
import optparse
import requests
from IPy import IP

reload(sys)
sys.setdefaultencoding('utf-8')
printLock = threading.Semaphore(1)  #lock Screen print
TimeOut = 3  #request timeout

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36','Connection':'close'}

class scan():

  def __init__(self,cidr,threads_num, ports, ipfile):
    self.threads_num = threads_num
    self.ipfile = ipfile
    #build ip queue
    self.IPs = Queue.Queue()

    if self.ipfile != "":
      assets = self.readFile()
      for ip, ports in assets:
        for port in ports:
          self.IPs.put('%s:%d' % (ip, port))
    else:
      for ip in IP(cidr):
        ip = str(ip)
        for port in ports:
          self.IPs.put('%s:%d' % (ip, port))

  def readFile(self):
    assets = []
    if os.path.exists(self.ipfile):
      with open(self.ipfile) as f:
        contents = f.read()
      if ':' in contents: # ip:port格式
        for line in contents.split('\n'):
          if line :
            ip_port = line.split(':')
            ip = ip_port[0]
            port = [int(ip_port[1])]
            assets.append((ip, port))
      else: # json格式
        for line in contents.split('\n'):
          try:
            jsline = json.loads(line)
          except:
            continue
          assets.append((jsline['ipaddr'], jsline['ports']))
      
    else:
      print 'file not exists'
    return assets


  def request(self):
    with threading.Lock():
      while self.IPs.qsize() > 0:
        ip = self.IPs.get()
        try:
          r = requests.Session().get('http://'+str(ip),headers=header,timeout=TimeOut)
          status = r.status_code
          title = re.search(r'<title>(.*)</title>', r.content) #get the title
          if title:
            title = title.group(1).strip().strip("\r").strip("\n")[:30]
          else:
            title = "None"
          banner = ''
          try:
            banner += r.headers['Server'][:20] #get the server banner
          except:pass
          printLock.acquire()
          try:
            print "|%-21s|%-6s|%-20s|%-30s|" % (ip,status,banner,title.decode('utf-8'))
            print "+---------------------+------+--------------------+------------------------------+"
            #Save log
            with open("./log/result.log",'a') as f:
              f.write("%s %s  %s  %s\n" % (ip,status,banner,title))
          except:
            traceback.print_exc()
            pass
        except:
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
    help = "[optional]e.g. 80,443 or 80-443, default 80")
  parser.add_option("-f", "--file", dest = "file",
    default = "", type = "str",
    help = "[optional]e.g. conf/ip.txt")
  (options, args) = parser.parse_args()

  # options.file = ".\conf\ip.txt"
  if len(args) < 1 and options.file == "":
    parser.print_help()
    sys.exit(0)
  elif len(args) == 1:
    try:
      IP(args[0])
    except:
      parser.print_help()
      sys.exit(0)

  cidr = '' if options.file != "" else args[0]

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

  s = scan(cidr=cidr,threads_num=options.threads_num, ports=ports, ipfile=options.file)
  s.run()
