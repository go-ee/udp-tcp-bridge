package utb

import (
	"context"
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

	go func() {
		buffer := make([]byte, o.MaxBufferSize)

		for {
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				panic(err)
			}

			log.Infof("received from UDP: bytes=%d from=%s\n", n, addr.String())

			n, err = tcpConn.Write(buffer[:n])
			if err != nil {
				panic(err)
			}
			log.Infof("written to TCP: bytes=%d to=%s\n", n, tcpConn.RemoteAddr())
		}
	}()

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

	raddr, err := net.ResolveTCPAddr("tcp", o.Target)
	if err != nil {
		panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	data := make([]byte, 1024)
	var n int
	if n, err = conn.Read(data); err != nil {
		panic(err)
	}
	log.Infof("packet-received and written: bytes=%d\n", n)
	writer.Write(data[:n])

}
