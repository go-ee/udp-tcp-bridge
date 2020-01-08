package utb

import (
	"context"
	"encoding/hex"
	"github.com/go-ee/utb/raw"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

type UdpTcpBridge struct {
	Name          string
	Source        string
	Target        string
	WrapPcapng    bool
	Raw           bool
	MaxBufferSize int
	Timeout       *time.Duration
	Context       context.Context
}

var (
	srcMac, _ = net.ParseMAC("AA:AA:AA:AA:AA:AA")
	dstMac, _ = net.ParseMAC("BB:BB:BB:BB:BB:BB")
	srcPort   = layers.UDPPort(40000)
	dstPort   = layers.UDPPort(60000)
	//srcIp =  ip(remAddr)
	srcIp   = net.ParseIP("10.0.2.15")
	dstIp   = net.ParseIP("10.0.2.255")
	options = gopacket.SerializeOptions{}
	rawUDP  = gopacket.NewSerializeBuffer()
)

func (o *UdpTcpBridge) Start(done func(label string)) {
	defer done("bridge")

	tcpServer, err := net.Listen("tcp", o.Target)
	if err != nil {
		panic(err)
	}
	defer tcpServer.Close()
	log.Infof("tcp server started for %s\n", o.Target)

	var tcpConn net.Conn
	if tcpConn, err = tcpServer.Accept(); err != nil {
		panic(err)
	}
	log.Infof("tcp connection established with %s\n", tcpConn.RemoteAddr())

	onPacket := o.buildTcpWriter(tcpConn)
	if o.Raw {
		o.udpReaderRaw(onPacket)
	} else {
		o.udpReader(onPacket)
	}

	select {
	case <-o.Context.Done():
		log.Infof("bridge stopped")
		err = o.Context.Err()
		if err != nil {
			panic(err)
		}
	}
	return
}

func (o *UdpTcpBridge) buildTcpWriter(tcpConn net.Conn) func(n int, bytes []byte, err error) {
	label := tcpConn.RemoteAddr().String()
	var onPacket func(n int, bytes []byte, err error)
	if o.WrapPcapng {
		ngWriter, err := pcapgo.NewNgWriter(tcpConn, layers.LinkTypeEthernet)
		if err != nil {
			panic(err)
		}
		onPacket = func(n int, data []byte, err error) {
			if err != nil {
				log.Fatalf("read error %v\n", err)
			} else {

				ci := gopacket.CaptureInfo{
					Timestamp:      time.Now(),
					Length:         n,
					CaptureLength:  n,
					InterfaceIndex: 0,
				}

				err = ngWriter.WritePacket(ci, data)
				if err != nil {
					log.Fatalf("can't write packet %v\n", err)
				}

				err = ngWriter.Flush()
				if err != nil {
					panic(err)
				}
				log.Infof("%v: NG written bytes=%d, data=%v, dump=\n%v\n", label, n, data, raw.Dump(data))
			}
		}
	} else {
		onPacket = func(n int, data []byte, err error) {
			if err != nil {
				log.Fatalf("read error %v\n", err)
			} else {
				_, err = tcpConn.Write(data)

				if err != nil {
					panic(err)
				}
				log.Infof("%v: written bytes=%d, data=%v, dump=\n%v\n", label, n, data, hex.Dump(data))
			}
		}
	}
	return onPacket
}

func (o *UdpTcpBridge) udpReader(onPacket func(n int, bytes []byte, err error)) {
	udpPacketConn, err := net.ListenPacket("udp", o.Source)
	if err != nil {
		panic(err)
	}
	defer udpPacketConn.Close()
	log.Infof("udp server started for %s\n", o.Source)

	udpData := make([]byte, o.MaxBufferSize)
	for {
		n, _, err := udpPacketConn.ReadFrom(udpData)
		data := udpData[:n]

		log.Infof("received payload bytes=%d, data=%v, dump=\n%v\n", n, data, hex.Dump(data))

		rawData := o.wrapAsRawUDP(data)
		rawDataN := len(rawData)

		onPacket(rawDataN, rawData, err)
	}
}

func (o *UdpTcpBridge) udpReaderRaw(onPacket func(n int, bytes []byte, err error)) {
	ipPortIdx := strings.LastIndex(o.Source, ":")
	ip := o.Source[0:ipPortIdx]
	portStr := o.Source[ipPortIdx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("can't parse port %v of %v", portStr, o.Source)
	}
	raw.Raw(ip, port, syscall.SOCK_RAW, syscall.IPPROTO_UDP, 0, 0, false, onPacket)
}

func (o *UdpTcpBridge) wrapAsRawUDP(data []byte) []byte {
	err := gopacket.SerializeLayers(rawUDP, options,
		&layers.Ethernet{SrcMAC: srcMac, DstMAC: dstMac},
		&layers.IPv4{
			SrcIP: srcIp,
			//DstIP: ip(addr),
			DstIP: dstIp,
		},
		&layers.UDP{SrcPort: srcPort, DstPort: dstPort},
		gopacket.Payload(data),
	)
	if err != nil {
		log.Fatalf("can't wrap as raw UDP %v", err)
	}
	ret := rawUDP.Bytes()
	return ret
}

func (o *UdpTcpBridge) StartUdpSender(done func(label string), reader io.Reader) {
	defer done("udp sender")

	raddr, err := net.ResolveUDPAddr("udp", o.Source)
	if err != nil {
		panic(err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	n, err := io.Copy(conn, reader)
	if err != nil {
		panic(err)
	}
	log.Infof("packet-written: bytes=%d\n", n)

	return
}

func (o *UdpTcpBridge) StartTcpReceiver(done func(label string), writer io.Writer) {
	defer done("tcp receiver")

	addr, err := net.ResolveTCPAddr("tcp", o.Target)
	if err != nil {
		panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if o.WrapPcapng {
		ngReader, err := pcapgo.NewNgReader(conn, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			panic(err)
		}
		data, ci, err := ngReader.ReadPacketData()
		if err != nil {
			panic(err)
		}
		log.Infof("packet-received over pcapng %v and written: bytes=%d\n", ci, len(data))
		writer.Write(data)
	} else {
		buffer := make([]byte, o.MaxBufferSize)
		n, err := conn.Read(buffer)
		if err != nil {
			panic(err)
		}
		data := buffer[:n]
		log.Infof("packet-received and written: bytes=%d\n", n)
		writer.Write(data[:n])
	}
}

func ip(addr net.Addr) (ret net.IP) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ret = addr.IP
	case *net.TCPAddr:
		ret = addr.IP
	}
	return
}
