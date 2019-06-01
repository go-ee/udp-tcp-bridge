package utb

import (
	"context"
	"io"
	"net"
	"sync"
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

func (o *UdpTcpBridge) Start(wg *sync.WaitGroup) {
	defer wg.Done()
	tcpServer, err := net.Listen("tcp", o.Target)
	if err != nil {
		panic(err)
	}
	defer tcpServer.Close()

	var tcpConn net.Conn
	if tcpConn, err = tcpServer.Accept(); err != nil {
		panic(err)
	}

	pc, err := net.ListenPacket("udp", o.Source)
	if err != nil {
		panic(err)
	}
	defer pc.Close()

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

func (o *UdpTcpBridge) StartUdpSender(wg *sync.WaitGroup, reader io.Reader) {
	defer wg.Done()

	raddr, err := net.ResolveUDPAddr("udp", o.Source)
	if err != nil {
		panic(err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	go func() {
		n, err := io.Copy(conn, reader)
		if err != nil {
			panic(err)
		}
		log.Infof("packet-written: bytes=%d\n", n)
	}()

	select {
	case <-o.Context.Done():
		log.Infof("sender stopped")
		err = o.Context.Err()
		if err != nil {
			panic(err)
		}
	}
}
