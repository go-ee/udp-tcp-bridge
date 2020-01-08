package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-ee/utb"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const flagName = "name"
const flagSource = "source"
const flagTarget = "target"
const flagPcapng = "pcapng"
const flagRaw = "raw"

func main() {

	name := "UDP-TCP-Bridge"
	runner := cli.NewApp()
	runner.Usage = name
	runner.Version = "1.0"
	runner.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  fmt.Sprintf("%v, %v", flagName, "n"),
			Usage: "name of the bridge, used for logging",
			Value: "urb",
		},
		&cli.StringFlag{
			Name:  fmt.Sprintf("%v, %v", flagSource, "s"),
			Usage: "UDP server address",
			Value: "localhost:47000",
		},
		&cli.StringFlag{
			Name:  fmt.Sprintf("%v, %v", flagTarget, "t"),
			Usage: "TCP server address",
			Value: "localhost:47001",
		},
		&cli.BoolFlag{
			Name:  flagPcapng,
			Usage: "wrap source UDP packets as PCAP-NG",
		},
		&cli.BoolFlag{
			Name:  flagRaw,
			Usage: "use UDP RAW Socket mode",
		},
	}

	flagSourceFile := "sourceFile"
	flagTargetFile := "targetFile"

	runner.Commands = []*cli.Command{
		{
			Name:  "start",
			Usage: "Start bringe",
			Action: func(c *cli.Context) (err error) {
				l(c).Info("start")
				var wg sync.WaitGroup
				done := func(label string) {
					l(c).Infof("%v completed", label)
					wg.Done()
				}

				bridge := buildBridge(c)
				wg.Add(1)
				bridge.Start(done)

				wg.Wait()

				return
			},
		}, {
			Name:  "test",
			Usage: "Start and transfer a source file to target file",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagSourceFile, "sf"),
					Usage: "source file to transfer",
				},
				&cli.StringFlag{
					Name:  fmt.Sprintf("%v, %v", flagTargetFile, "tf"),
					Usage: "target file to write the transferred file",
				},
			},
			Action: func(c *cli.Context) (err error) {
				l(c).Info("test")
				var wg sync.WaitGroup
				done := func(label string) {
					l(c).Infof("%v completed", label)
					wg.Done()
				}

				bridge := buildBridge(c)
				wg.Add(1)
				go bridge.Start(done)

				var targetFile *os.File
				var targetFilePath string
				if targetFilePath, err = filepath.Abs(c.String(flagTargetFile)); err != nil {
					return
				}

				if targetFile, err = os.OpenFile(targetFilePath, os.O_APPEND|os.O_WRONLY, 0600); err != nil {
					if targetFile, err = os.Create(c.String(flagTargetFile)); err != nil {
						log.WithFields(log.Fields{
							flagTargetFile: targetFilePath,
						}).Info("can't create file")
						return
					}
				}

				targetWriter := bufio.NewWriter(targetFile)
				doneFlush := func(label string) {
					targetWriter.Flush()
					done(label)
					os.Exit(0)
				}
				wg.Add(1)
				go bridge.StartTcpReceiver(doneFlush, targetWriter)

				time.Sleep(100 * time.Millisecond)

				var sourceFilePath string
				if sourceFilePath, err = filepath.Abs(c.String(flagSourceFile)); err != nil {
					log.WithFields(log.Fields{
						flagSourceFile: c.String(flagSourceFile),
					}).Info("can't find the file")
					return
				}

				var sourceFile *os.File
				if sourceFile, err = os.Open(sourceFilePath); err != nil {
					return
				}

				wg.Add(1)
				go bridge.StartUdpSender(done, sourceFile)

				wg.Wait()

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
		flagName:   c.String(flagName),
		flagSource: c.String(flagSource),
		flagTarget: c.String(flagTarget),
		flagPcapng: c.String(flagPcapng),
		flagRaw:    c.String(flagRaw),
	})
}

func buildBridge(c *cli.Context) *utb.UdpTcpBridge {
	duration := time.Duration(10000)
	return &utb.UdpTcpBridge{
		c.String(flagName),
		c.String(flagSource),
		c.String(flagTarget),
		c.Bool(flagPcapng),
		c.Bool(flagRaw),
		1024,
		&duration,
		context.Background()}
}
