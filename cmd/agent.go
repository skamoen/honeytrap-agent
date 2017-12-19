package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/fatih/color"
	cli "gopkg.in/urfave/cli.v1"

	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap-agent/server"

	_ "net/http/pprof"
)

var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
	{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
	{{end}}{{if .Flags}}
FLAGS:
	{{range .Flags}}{{.}}
	{{end}}{{end}}
VERSION:
` + server.Version +
	`{{ "\n"}}`

var log = logging.MustGetLogger("honeytrap-agent")

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func serve(c *cli.Context) error {
	options := []server.OptionFn{
		server.WithToken(),
	}

	if !c.Args().Present() {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("No target server set.")), 1)
		return ec
	}

	options = append(options, server.WithServer(c.Args().First()))

	srvr, err := server.New(
		options...,
	)

	if err != nil {
		ec := cli.NewExitError(err.Error(), 1)
		return ec
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := make(chan os.Signal, 1)
		signal.Notify(s, os.Interrupt)
		signal.Notify(s, syscall.SIGTERM)

		select {
		case <-s:
			cancel()
		}
	}()

	log.Info("Honeytrap Agent starting...")
	defer log.Info("Honeytrap Agent stopped.")

	srvr.Run(ctx)
	return nil
}

func New() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(c.App.Writer,
			`Version: %s
Release-Tag: %s
Commit-ID: %s
`, color.YellowString(server.Version), color.YellowString(server.ReleaseTag), color.YellowString(server.CommitID))
	}

	app := cli.NewApp()
	app.Name = "honeytrap-agent"
	app.Usage = "Honeytrap Agent"
	app.Commands = []cli.Command{}

	app.Before = func(context *cli.Context) error {
		return nil
	}

	app.Action = serve

	app.Flags = append(app.Flags, []cli.Flag{}...)

	return app
}
