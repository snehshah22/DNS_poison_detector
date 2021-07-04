package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	//"strconv"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	handle        *pcap.Handle
	InetAddr      string
	SrcIP         string
	DstIP         string
	SrcPort       string
	DstPort       string
	DnsServerPort string
	VicPort       string
	flag          int
)

func detectofflineTraffic(pcapFile string, bpfFilter string) {
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		flag = 0
		handle.SetBPFFilter(bpfFilter)
		request_map := make(map[int]int)
		response_map := make(map[int]int)
		answer_map := make(map[int]string)
		timestamp_map := make(map[int]time.Time)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			udp, _ := udpLayer.(*layers.UDP)

			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				dnsId := int(dns.ID)
				// last_ans1 := answer_map[dnsId]

				last_timestamp := timestamp_map[dnsId]
				timestamp_map[dnsId] = packet.Metadata().Timestamp

				for _, dnsQuestion := range dns.Questions {
					domain := string(dnsQuestion.Name)
					_, found_query := request_map[dnsId]
					_, found_response := response_map[dnsId]
					if udp.DstPort == 53 {
						if found_query {
							request_map[dnsId] += 1
						} else {
							request_map[dnsId] = 1
						}
					} else if udp.DstPort != 53 {
						if found_response {
							response_map[dnsId] += 1
						} else {
							response_map[dnsId] = 1
						}
					}
					var last_ans string

					var last_ans1 string
					last_ans1 = answer_map[dnsId]
					answer_map[dnsId] = ""
					for _, dnsAnswer := range dns.Answers {
						if dnsAnswer.IP.String() != "<nil>" {
							//last_ans = answer_map[dnsId]

							answer_map[dnsId] = answer_map[dnsId] + " " + dnsAnswer.IP.String()
							_ = last_ans

						}
					}
					time_diff := last_timestamp.Sub(timestamp_map[dnsId])
					if response_map[dnsId] > request_map[dnsId] && time_diff < 1*time.Second && answer_map[dnsId] != last_ans1 {
						timestamp := last_timestamp.Format(time.RFC3339)
						flag = 1

						fmt.Println(fmt.Sprintf("%s DNS poisoning attempt", timestamp))
						fmt.Println(fmt.Sprintf("TXID: %s Request %s", []byte(strconv.FormatInt(int64(dnsId), 16)), domain))
						fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", answer_map[dnsId]))
						fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", last_ans1))
						delete(response_map, dnsId)
						delete(request_map, dnsId)
						delete(timestamp_map, dnsId)
						delete(answer_map, dnsId)
					}
				}
			}
		}
		if flag == 0 {
			fmt.Println("no spoof detected")
		}

	}
}

func detectLiveTraffic(interfaceName string, bpfFilter string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err)
	}

	handle, err = pcap.OpenLive(devices[0].Name, 1024, true, 1*time.Second)
	if err != nil {
		fmt.Println(err)
	}
	handle.SetBPFFilter(bpfFilter)
	request_map := make(map[int]int)
	response_map := make(map[int]int)
	answer_map := make(map[int]string)
	timestamp_map := make(map[int]time.Time)
	//var uniq int64

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			dnsId := int(dns.ID)

			last_timestamp := timestamp_map[dnsId]
			timestamp_map[dnsId] = packet.Metadata().Timestamp
			//uniq = 0
			for _, dnsQuestion := range dns.Questions {
				domain := string(dnsQuestion.Name)
				_, found_query := request_map[dnsId]
				_, found_response := response_map[dnsId]
				if udp.DstPort == 53 {
					if found_query {
						request_map[dnsId] += 1
					} else {
						request_map[dnsId] = 1
					}
				} else if udp.DstPort != 53 {
					if found_response {
						response_map[dnsId] += 1
					} else {
						response_map[dnsId] = 1
					}
				}
				//var last_ans string
				var last_ans1 string

				last_ans1 = answer_map[dnsId]
				answer_map[dnsId] = ""
				for _, dnsAnswer := range dns.Answers {
					//var last int64
					//last = 1

					if dnsAnswer.IP.String() != "<nil>" {
						//last_ans = answer_map[dnsId]
						answer_map[dnsId] = answer_map[dnsId] + " " + dnsAnswer.IP.String()
						//_ = last_ans

					}

				}
				time_diff := last_timestamp.Sub(timestamp_map[dnsId])
				if response_map[dnsId] > request_map[dnsId] && time_diff < 1*time.Second /*&& answer_map[dnsId] != last_ans1*/ {
					timestamp := last_timestamp.Format(time.RFC3339)
					flag = 1
					fmt.Println(fmt.Sprintf("%s DNS poisoning attempt", timestamp))
					fmt.Println(fmt.Sprintf("TXID: %s Request %s", []byte(strconv.FormatInt(int64(dnsId), 16)), domain))
					fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", answer_map[dnsId]))
					fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", last_ans1))
					delete(response_map, dnsId)
					delete(request_map, dnsId)
					delete(timestamp_map, dnsId)
					delete(answer_map, dnsId)
				}
				//uniq = uniq + 1
			}

		}

	}
}

func main() {

	devices, _ := pcap.FindAllDevs()

	var interfaces string = devices[0].Name
	var bpfstr string = "udp"
	var pcapname string = ""
	args1 := os.Args[1:]
	var ic = 0
	var rc = 0
	var bc = 0

	for i := 0; i < len(args1); i = i + 2 {
		if args1[i] == "-r" {
			if rc == 1 {
				fmt.Println("2 times -r not accepted")
				os.Exit(1)
			}
			rc = 1
			pcapname = args1[i+1]
			if strings.Contains(pcapname, " ") {
				fmt.Println("enter val after -r")
				os.Exit(1)
			}
			if pcapname == "-r" || pcapname == "-s" || pcapname == "-i" {
				fmt.Println("incorrect expression. enter value after -r")
				os.Exit(1)
			}
		} else if args1[i] == "-i" {
			if ic == 1 {
				fmt.Println("2 times -i not accepted")
				os.Exit(1)
			}
			ic = 1
			interfaces = args1[i+1]
			if interfaces == "-r" || interfaces == "-f" || interfaces == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else {
			if bc == 1 {
				fmt.Println("2 times bpf not accepted")
				os.Exit(1)
			}
			bc = 1
			bpfstr = args1[i]
			i = i - 1
		}
	}

	_ = interfaces
	_ = pcapname
	_ = bpfstr
	fmt.Println("interface= ", interfaces)
	fmt.Println("tracefile= ", pcapname)
	fmt.Println("bpfstr= ", bpfstr)

	if len(pcapname) != 0 && len(interfaces) != 0 {
		fmt.Println("only -r will work")
		interfaces = ""
	}
	if len(pcapname) == 0 {
		detectLiveTraffic(interfaces, bpfstr)
	}
	if len(interfaces) == 0 {
		detectofflineTraffic(pcapname, bpfstr)
	}

}
