fwall
=====

   Scrapes firewall logs to generate filter usage, used to refine iptables rulesets 
with extended sample sets. Currently only accepts input through pipes.


Help
====

usage: fwall.py [-h] [-H] [-p] [-q] [-t]

Firewall log parser; generates quick or host reports exclusively.

optional arguments:
  -h, --help       show this help message and exit
  -H, --host       Report on parsed Host Data
  -p, --port       Report on parsed port data
  -q, --quick      Generate Quick Report, can not be part of a Host report
  -t, --timestamp  Report with timestamps (Increases Resource Consumption
                   Considerably)


Example Usage
=============

  hello@thar fwall$ cat /var/log/firewall.log | ./fwall -q  
    [+] 1.1.1.1         => 58968 #10709, 35303 #553, 113   #1  
    [+] 1.1.1.2         => 6977  #1713, 6977  #54  
    [+] 1.1.1.3         => 6957  #1643, 6957  #40  
    [+] 1.1.1.4         => 6977  #1416, 6977  #18  
    [+] 1.1.1.5         => 6977  #1407 

  hello@thar fwall$ cat /var/log/firewall.log | ./fwall -H  
    [+] 1.1.1.1         : 11263 Total hits 
    [+] 1.1.1.2         : 1767 Total hits  
    [+] 1.1.1.3         : 1683 Total hits  
    [+] 1.1.1.4         : 1434 Total hits  
    [+] 1.1.1.5         : 1407 Total hits  


  hello@thar fwall$ cat /var/log/firewall.log | ./fwall -Hp  
  [+] 213.92.8.4      : 11263 Total hits

  [ TCP ]

   Port: 35303 => 553 Hits  
   Port: 58968 => 10709 Hits  
   Port: 113   => 1 Hits  

