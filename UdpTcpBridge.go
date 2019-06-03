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

	pc, err := net.ListenPacket("udp", o.Source)
	if err != nil {
		panic(err)
	}
	defer pc.Close()
	log.Infof("udp server started for %s\n", o.Source)

	if o.WrapPcapng {
		ngWriter, err := pcapgo.NewNgWriter(tcpConn, layers.LinkTypeEthernet)
		if err != nil {
			panic(err)
		}
		go o.tcpNgWriter(tcpConn.RemoteAddr().String(), pc, ngWriter)
	} else {
		go o.tcpWriter(tcpConn.RemoteAddr().String(), pc, tcpConn)
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

func (o *UdpTcpBridge) tcpWriter(label string, pc net.PacketConn, tcpConn net.Conn) {
	buffer := make([]byte, o.MaxBufferSize)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			panic(err)
		}

		log.Infof("received from UDP: bytes=%d from=%s\n", n, addr.String())

		data := buffer[:n]

		n, err = tcpConn.Write(data)

		if err != nil {
			panic(err)
		}
		log.Infof("%v: written to TCP: bytes=%d\n", label, n)
	}
}

func (o *UdpTcpBridge) tcpNgWriter(label string, pc net.PacketConn, ngWriter *pcapgo.NgWriter) {
	buffer := make([]byte, o.MaxBufferSize)
	for {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			panic(err)
		}

		log.Infof("received from UDP: bytes=%d from=%s\n", n, addr.String())

		data := buffer[:n]

		ci := gopacket.CaptureInfo{
			Timestamp:      time.Unix(0, 0).UTC(),
			Length:         len(data),
			CaptureLength:  len(data),
			InterfaceIndex: 0,
		}
		err = ngWriter.WritePacket(ci, data)
		if err != nil {
			panic(err)
		}
		err = ngWriter.Flush()
		if err != nil {
			panic(err)
		}

		log.Infof("%v: written to NG TCP: bytes=%d\n", label, n)
	}
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
