package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"strings"
	"time"
)

const flagNetwork = "network"
const flagFilter = "filter"
const flagSrcIp = "source"
const flagDstIp = "dest"

func main() {

	name := "OpenLive"
	runner := cli.NewApp()
	runner.Usage = name
	runner.Version = "1.0"

	runner.Commands = []cli.Command{
		{
			Name:  "devices",
			Usage: "List network devices",
			Action: func(c *cli.Context) (err error) {
				l(c).Info("devices")
				printDevices()
				return
			},
		}, {
			Name:  "openDevice",
			Usage: "Open and listen to a device",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagNetwork, "n"),
					Usage: "device to open",
				},
				cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagFilter, "f"),
					Usage: "packet filter to apply",
					Value: "",
				},
				cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagSrcIp, "s"),
					Usage: "consider packets only with the source ip",
					Value: "",
				},
				cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagDstIp, "d"),
					Usage: "consider packets only with the dest ip",
					Value: "",
				},
			},
			Action: func(c *cli.Context) (err error) {
				l(c).Info("open device")
				openDevice(c.String(flagNetwork), c.String(flagFilter), c.String(flagSrcIp), c.String(flagDstIp))

				return
			},
		},
	}

	if err := runner.Run(os.Args); err != nil {
		log.Infof("run failed, %v, %v", os.Args, err)
	}
	log.Infof("done %v", os.Args)
}

func l(c *cli.Context) *log.Entry {
	return log.WithFields(log.Fields{
		flagNetwork: c.String(flagNetwork),
		flagFilter:  c.String(flagFilter),
		flagSrcIp:   c.String(flagSrcIp),
		flagDstIp:   c.String(flagDstIp),
	})
}

var (
	//device      string = "eth0"
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func openDevice(device string, filter string, filterSrcIp string, filterDstIp string) {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if len(filter) > 0 {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("apply filter: %v", filter)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet, filterSrcIp, filterDstIp)
	}
}

func printPacketInfo(packet gopacket.Packet, onlySrcIp string, onlyDstIp string) {
	if onlySrcIp != "" || onlyDstIp != "" {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			log.Infof("skip %v:\n", packet)
			return
		}
		ip, _ := ipLayer.(*layers.IPv4)
		if (onlySrcIp != "" && ip.SrcIP.String() != onlySrcIp) ||
			(onlyDstIp != "" && ip.DstIP.String() != onlyDstIp) {
			log.Infof("skip %v:\n", packet)
			return
		}
	}

	log.Infof("PACKET:\n")
	log.Infof("STRING:%s\n", packet.String())
	log.Infof("BYTES:%v\n", packet.Data())
	log.Infof("DUMP:%v\n", packet.Dump())

	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		log.Info("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		log.Info("Source MAC: ", ethernetPacket.SrcMAC)
		log.Info("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		log.Info("Ethernet type: ", ethernetPacket.EthernetType)
		log.Info()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		log.Info("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		log.Infof("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		log.Info("Sequence number: ", tcp.Seq)
		log.Info()
	}

	// Iterate over all layers, printing out each layer type
	log.Info("All packet layers:")
	for _, layer := range packet.Layers() {
		log.Info("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		log.Info("Application layer/Payload found.")
		log.Infof("STRING:%s\n", applicationLayer.Payload())
		log.Infof("BYTES:%v\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			log.Info("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Info("Error decoding some part of the packet:", err)
	}
}

func printDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// Print device information
	log.Info("Devices found:")
	for _, device := range devices {
		log.Info("\nName: ", device.Name)
		log.Info("Description: ", device.Description)
		log.Info("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			log.Info("- IP address: ", address.IP)
			log.Info("- Subnet mask: ", address.Netmask)
		}
	}
}
