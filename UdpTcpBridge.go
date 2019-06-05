package utb

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

type UdpTcpBridge struct {
	Name          string
	Source        string
	Target        string
	WrapPcapng    bool
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

	udpPacketConn, err := net.ListenPacket("udp", o.Source)
	if err != nil {
		panic(err)
	}
	defer udpPacketConn.Close()
	log.Infof("udp server started for %s\n", o.Source)

	if o.WrapPcapng {
		ngWriter, err := pcapgo.NewNgWriter(tcpConn, layers.LinkTypeEthernet)
		if err != nil {
			panic(err)
		}
		go o.tcpNgWriter(tcpConn.RemoteAddr(), udpPacketConn, ngWriter)
	} else {
		go o.tcpWriter(tcpConn.RemoteAddr(), udpPacketConn, tcpConn)
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

func (o *UdpTcpBridge) tcpWriter(remAddr net.Addr, udpPacketConn net.PacketConn, tcpConn net.Conn) {
	label := remAddr.String()
	udpData := make([]byte, o.MaxBufferSize)
	for {
		udpDataN, addr, err := udpPacketConn.ReadFrom(udpData)
		if err != nil {
			panic(err)
		}

		data := udpData[:udpDataN]

		log.Infof("received from UDP: bytes=%d from=%s, payload=%v\n", udpDataN, addr.String(), data)

		rawData := o.rawUDP(data)
		rawDataN := len(rawData)

		_, err = tcpConn.Write(rawData)

		if err != nil {
			panic(err)
		}
		log.Infof("%v: written to TCP: payload.bytes=%d, rawData.bytes=%d, rawData=%v\n",
			label, udpDataN, rawDataN, rawData)
	}
}

func (o *UdpTcpBridge) tcpNgWriter(remAddr net.Addr, udpPacketConn net.PacketConn, ngWriter *pcapgo.NgWriter) {
	label := remAddr.String()

	udpData := make([]byte, o.MaxBufferSize)
	for {
		udpN, addr, err := udpPacketConn.ReadFrom(udpData)
		if err != nil {
			panic(err)
		}

		data := udpData[:udpN]

		log.Infof("received from UDP: bytes=%d from=%s, payload=%v\n", udpN, addr.String(), data)

		rawData := o.rawUDP(data)
		rawDataN := len(rawData)

		ci := gopacket.CaptureInfo{
			Timestamp:      time.Unix(0, 0).UTC(),
			Length:         rawDataN,
			CaptureLength:  rawDataN,
			InterfaceIndex: 0,
		}

		err = ngWriter.WritePacket(ci, rawData)
		if err != nil {
			panic(err)
		}
		err = ngWriter.Flush()
		if err != nil {
			panic(err)
		}
		log.Infof("%v: written to NG TCP: payload.bytes=%d, rawData.bytes=%d, rawData=%v\n",
			label, udpN, rawDataN, rawData)
	}
}

func (o *UdpTcpBridge) rawUDP(data []byte) []byte {
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
		panic(err)
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
