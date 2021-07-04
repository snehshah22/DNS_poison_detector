# DNS_poison_detector
Captures the traffic from a network interface in promiscuous mode and detects DNS poisoning attack attempts.

Specification
go run dnsdetect.go [-i interface] [-r tracefile] expression
NOTE: PLEASE TYPE THE FULL URL WITH "WWW" IN THE SEARCH BOX IN WEB BROWSER. EG. www.tcpdump.org , www.bankofamerica.com

Usage:
The code takes 3 parameters

1) -i interface.
The interface to be monitored can be specified. Default interface is found by FindAllDevs, if no interface is specified. Invalid interface 
name will produce errors.

2) -r tracefile
the pcap tracefile will be read for offline analysis.

3) BPF expression
If a BPF expression is provided, then the network traffic will be filtered based on the filter expression. Enter the BPF filter in quotes.

Just like tcpdump, there is no particular order in which the parameters need to be entered.
The program needs to run in sudo to avoid permission realted errors.
NOTE: PLEASE TYPE THE FULL URL WITH "WWW" IN THE SEARCH BOX.
If both tracefile and interface are provided, then only the tracefile will by analysed.

Implementation Details:
Once all the parameters are gathered from the command line arguments, there a the detectlivetraffic or detectofflinetraffic function 
is called and it works in the following manner:
- handle is obtained using openlive or openoffline and BFP filter is applied
- 4 hashmap are created with key as transaction ID and values as query count, response count, timestamp and IP answer.
- request count is the number of queries sent with that transaction ID.
- response count is the number of responses sent with that transaction ID.
- timestamp stores the time of the last response with a particular transaction ID.
- Answer IP map stores the IP address of the in the first answer.
- If the number of response for a particular trans ID is more than the number of requests, then the time condition is checked. If the time
between the 2 packets is more than a threshold of 1 second, then the answer is checked. If the answers are the same, then it is possible that
the true response was sent twice by DNS. In this case, it s not considered as a spoof.
- If the timestamp difference is greater than threshold, then it is possible that the transactionID is reused for a different query. In this
 case it is not considered as a spoof.

Output sample
1) sudo go run dnsdetect.go
interface=  ens33
tracefile=  
bpfstr=  udp
2021-04-08T20:31:51-07:00 DNS poisoning attempt
TXID: 1d33 Request www.tcpdump.org
ANSWER 1: [192.139.46.66]
ANSWER 2: [159.89.89.188]
2021-04-08T20:32:27-07:00 DNS poisoning attempt
TXID: 4d36 Request www.bankofamerica.com
ANSWER 1: [171.161.100.100]
ANSWER 2: [192.168.2.128]

(Here www.tcpdump.org and www.bankofamerica.com were mentioned in the hostnames file in dnspoison.go)

2) sudo go run dnsdetect.go hw3.pcap
interface=  ens33
tracefile=  hw3.pcap
bpfstr=  udp
only -r will work
no spoof detected

(hw3.pcap was created without running any spoofing program)

3) sudo go run dnsdetect.go hw3spoof.pcap
interface=  ens33
tracefile=  hw3spoof.pcap
bpfstr=  udp
only -r will work
2021-04-06T17:50:15-07:00 DNS poisoning attempt
TXID: a49 Request www.tcpdump.org
ANSWER 1: [159.89.89.188]
ANSWER 2: [192.139.46.66]
2021-04-06T17:50:19-07:00 DNS poisoning attempt
TXID: 94a9 Request www.bankofamerica.com
ANSWER 1: [192.168.85.128]
ANSWER 2: [171.161.100.100]
2021-04-06T17:51:30-07:00 DNS poisoning attempt
TXID: 258c Request www.bankofamerica.com
ANSWER 1: [192.168.85.128]
ANSWER 2: [171.161.116.100]

(Here www.tcpdump.org and www.bankofamerica.com were mentioned in the hostnames file in dnspoison.go)

4) sudo go run dnsdetect.go hw1.pcap
interface=  ens33
tracefile=  hw1.pcap
bpfstr=  udp
only -r will work
no spoof detected
