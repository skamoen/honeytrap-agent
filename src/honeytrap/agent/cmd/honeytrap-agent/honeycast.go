package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/codegangsta/cli"
	"github.com/op/go-logging"
	"github.com/pkg/profile"

	agent "honeytrap/agent"

	_ "net/http/pprof"
)

var version = "0.1"

var log = logging.MustGetLogger("honeycast")

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

var cmdServe = cli.Command{
	Name:        "serv",
	Usage:       "This command should only be called by SSH shell",
	Description: `Serv provide access auth for repositories`,
	Action:      runServe,
	Flags:       []cli.Flag{},
}

func runServe(c *cli.Context) {
	configFile := c.GlobalString("config")
	config, err := agent.NewConfig()

	if err != nil {
		fmt.Fprintf(os.Stdout, err.Error())
		return
	}

	if err := config.Load(configFile); err != nil {
		fmt.Fprintf(os.Stdout, err.Error())
		return
	}

	var profiler interface {
		Stop()
	} = nil

	if c.GlobalBool("cpu-profile") {
		log.Info("CPU profiler started.")
		profiler = profile.Start(profile.CPUProfile, profile.ProfilePath("."), profile.NoShutdownHook)
	} else if c.GlobalBool("mem-profile") {
		log.Info("Memory profiler started.")
		profiler = profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook)
	}

	var a = agent.New(config)
	a.Start()

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	signal.Notify(s, syscall.SIGTERM)

	<-s

	if profiler != nil {
		profiler.Stop()
	}

	log.Info("Honeytrap Agent stopped.")

	os.Exit(0)
}

func main() {
	app := cli.NewApp()
	app.Name = "honeycast-agent"
	app.Usage = "Honeycast Agent"
	app.Version = version
	app.Commands = []cli.Command{
		cmdServe,
	}

	app.Before = func(context *cli.Context) error {
		return nil
	}

	app.Flags = append(app.Flags, []cli.Flag{
		cli.StringFlag{"config, c", "config.yaml", "specifies the location of the config file", ""},
		cli.BoolFlag{"cpu-profile", "Enable cpu profiler", ""},
		cli.BoolFlag{"mem-profile", "Enable memory profiler", ""},
	}...)

	app.Run(os.Args)
}
