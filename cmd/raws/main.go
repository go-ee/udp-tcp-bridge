package main

import (
	"fmt"
	"github.com/go-ee/utb/raw"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"syscall"
)

const flagIp = "ip"
const flagPort = "port"
const flagType = "type"
const flagProto = "proto"
const flagBytes = "bytes"
const flagMinBytes = "minBytes"
const flagMaxBytes = "maxBytes"
const flagLayers = "layers"

func main() {

	name := "RawSocket"
	runner := cli.NewApp()
	runner.Usage = name
	runner.Version = "1.0"

	runner.Commands = []*cli.Command{
		{
			Name:  "listen",
			Usage: "Open Raw socket and dump packets",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  flagIp,
					Usage: "ip to open",
				},
				&cli.IntFlag{
					Name:  fmt.Sprintf("%v, p", flagPort),
					Usage: "port to open",
				},
				&cli.IntFlag{
					Name: fmt.Sprintf("%v, t", flagType),
					Usage: "default RAW (3), available 	SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_RAW=3, SOCK_SEQPACKET=5",
					Value: syscall.SOCK_RAW,
				},
				&cli.IntFlag{
					Name:  fmt.Sprintf("%v, pr", flagProto),
					Usage: "default UDP (17), available IPPROTO_IP=0,IPPROTO_IPV6=0x29, IPPROTO_TCP=6, IPPROTO_UDP=17",
					Value: syscall.IPPROTO_UDP,
				},
				&cli.BoolFlag{
					Name:  fmt.Sprintf("%v, b", flagBytes),
					Usage: "bytes to log?",
				},
				&cli.IntFlag{
					Name:  fmt.Sprintf("%v, min", flagMinBytes),
					Usage: "filter bytes >= min",
				},
				&cli.IntFlag{
					Name:  fmt.Sprintf("%v, max", flagMaxBytes),
					Usage: "filter bytes <= max",
				},
				&cli.BoolFlag{
					Name:  fmt.Sprintf("%v, l", flagLayers),
					Usage: "decode layers?",
				},
			},
			Action: func(c *cli.Context) (err error) {
				l(c).Info("Raw")
				bytes := c.Bool(flagBytes)
				raw.Raw(c.String(flagIp), c.Int(flagPort), c.Int(flagType), c.Int(flagProto),
					c.Int(flagMinBytes), c.Int(flagMaxBytes), c.Bool(flagLayers),
					func(n int, data []byte, err error) {
						if err != nil {
							log.Infof("read error %v\n", err)
						} else {
							if bytes {
								log.Infof("bytes=%d, data=%v, dump=\n%v\n", n, data, raw.Dump(data))
							} else {
								log.Infof("bytes=%d, data=%v, dump=\n%v\n", n, data, raw.Dump(data))
							}
						}
					})
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
		flagType:     c.Int(flagType),
		flagProto:    c.Int(flagProto),
		flagMinBytes: c.Int(flagMinBytes),
		flagMaxBytes: c.Int(flagMaxBytes),
		flagLayers:   c.Bool(flagLayers),
	})
}
