package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"net"
	"os"
	"syscall"
)

const flagIp = "ip"
const flagPort = "port"
const flagIpProto = "proto"
const flagMinBytes = "minBytes"
const flagMaxBytes = "maxBytes"

func main() {

	name := "RawSocket"
	runner := cli.NewApp()
	runner.Usage = name
	runner.Version = "1.0"

	runner.Commands = []cli.Command{
		{
			Name:  "listen",
			Usage: "Open raw socket and dump packets",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  flagIp,
					Usage: "ip to open",
				},
				cli.IntFlag{
					Name:  fmt.Sprintf("%v, %v", flagPort, "p"),
					Usage: "port to open",
				},
				cli.IntFlag{
					Name:  fmt.Sprintf("%v, %v", flagIpProto),
					Usage: "default UDP (17)",
					Value: syscall.IPPROTO_UDP,
				},
				cli.IntFlag{
					Name:  fmt.Sprintf("%v, %v", flagMinBytes, "min"),
					Usage: "filter bytes >= min",
				},
				cli.IntFlag{
					Name:  fmt.Sprintf("%v, %v", flagMaxBytes, "max"),
					Usage: "filter bytes <= max",
				},
			},
			Action: func(c *cli.Context) (err error) {
				l(c).Info("raw")
				raw(c.String(flagIp), c.Int(flagPort), c.Int(flagIpProto), c.Int(flagMinBytes), c.Int(flagMaxBytes))

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
		flagIp:       c.String(flagIp),
		flagPort:     c.Int(flagPort),
		flagIpProto:  c.Int(flagIpProto),
		flagMinBytes: c.Int(flagMinBytes),
		flagMaxBytes: c.Int(flagMaxBytes),
	})
}

func raw(ip string, port int, ipProto int, minBytes int, maxBytes int) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipProto)
	if err != nil {
		log.Warnf("can't syscall.Socket, %v", err)
		return
	}
	parsed := net.ParseIP(ip)
	ip4 := [4]byte{parsed[0], parsed[1], parsed[3], parsed[4]}
	sa := &syscall.SockaddrInet4{
		Addr: ip4,
		Port: port,
	}
	e := syscall.Bind(fd, sa)
	if e != nil {
		log.Warnf("can't syscall.Bind, %v", e)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd))
	log.Infof("Listening %v:%v, proto=%v, minBytes=%v, maxBytes=%v", ip, port, ipProto, minBytes, maxBytes)
	for {
		buf := make([]byte, 1024)
		numRead, err := f.Read(buf)
		if err != nil {
			log.Infof("problems @ location 2")
		}
		if (minBytes == 0 || numRead >= minBytes) && (maxBytes == 0 || numRead <= maxBytes) {
			log.Infof("bytes=%d, dump=%v\n", numRead, buf[:numRead])
		}
	}

}
