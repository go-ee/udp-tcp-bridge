package raw

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"syscall"
)

var (
	eth     layers.Ethernet
	ip      layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	dns     layers.DNS
	payload gopacket.Payload
)

func Raw(ipAddr string, port int, typ int, proto int, minBytes int, maxBytes int, decodeLayers bool,
	onPacket func(n int, bytes []byte, err error)) {
	fd, err := syscall.Socket(syscall.AF_INET, typ, proto)
	if err != nil {
		log.Warnf("can't syscall.Socket, %v", err)
		return
	}

	p := net.ParseIP(ipAddr)
	var ip4 [4]byte
	if len(p) <= 0 {
		log.Infof("use 0.0.0.0 instead of %v, %v", ipAddr, p)
		ip4 = [4]byte{0, 0, 0, 0}
	} else {
		ip4 = [4]byte{p[12], p[13], p[14], p[15]}
	}
	sa := &syscall.SockaddrInet4{
		Addr: ip4,
		Port: port,
	}
	e := syscall.Bind(fd, sa)
	if e != nil {
		log.Warnf("can't syscall.Bind, %v", e)
	}

	// Faster, predefined layer parser that doesn't make copies of the layer slices
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip,
		&udp,
		&payload)

	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd))
	log.Infof("Listening %v:%v, proto=%v, minBytes=%v, maxBytes=%v", ipAddr, port, proto, minBytes, maxBytes)
	for {
		buf := make([]byte, 1024)
		numRead, err := f.Read(buf)

		if err != nil {
			onPacket(0, nil, err)
		} else if (minBytes <= 0 || numRead >= minBytes) && (maxBytes <= 0 || numRead <= maxBytes) {
			data := buf[:numRead]

			if decodeLayers {
				var decoded []gopacket.LayerType
				err = parser.DecodeLayers(data, &decoded)
				if err != nil {
					log.Infof("skip packet, decoding not possible, %v, decoded=%v, bytes=%v, data=%v, dump=%v",
						err, decoded, numRead, data, Dump(data))
				} else {
					onPacket(numRead, data, err)
				}
			} else {
				onPacket(numRead, data, err)
			}
		}
	}
}

func Dump(data []byte) string {
	return hex.Dump(data)
}
