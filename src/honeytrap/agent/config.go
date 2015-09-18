package agent

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/imdario/mergo"

	"gopkg.in/yaml.v2"
)

type (
	Config struct {
		Token    string                   `yaml:"token"`
		Host     string                   `yaml:"host"`
		TLS      TLSConfig                `yaml:"tls"`
		Services map[string]ServiceConfig `yaml:"services"`
	}

	TLSConfig struct {
		Enabled bool `yaml:"enabled"`
	}

	ServiceConfig struct {
		Address string `yaml:"address"`
		Host    string `yaml:"host"`
	}
)

type Loglevel string

func (loglevel *Loglevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var loglevelString string
	err := unmarshal(&loglevelString)
	if err != nil {
		return err
	}

	loglevelString = strings.ToLower(loglevelString)
	switch loglevelString {
	case "error", "warn", "info", "debug":
	default:
		return fmt.Errorf("Invalid loglevel %s Must be one of [error, warn, info, debug]", loglevelString)
	}

	*loglevel = Loglevel(loglevelString)
	return nil
}

type Delay time.Duration

func (t *Delay) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var s string
	if err := unmarshal(&s); err != nil {
		panic(err)
	}

	var d time.Duration
	d, err = time.ParseDuration(s)
	if err != nil {
		log.Error("Error parsing duration (%s): %s", s, err.Error())
		return err
	}

	*t = Delay(d)
	return
}

var DefaultConfig = Config{
	Token: "",
	TLS: TLSConfig{
		Enabled: false,
	},
}

func NewConfig() (*Config, error) {
	c := DefaultConfig
	return &c, nil
}

func (c *Config) Load(file string) error {
	data, err := ioutil.ReadFile(file)

	if err != nil {
		return err
	}

	conf := Config{}
	err = yaml.Unmarshal(data, &conf)

	if err != nil {
		return err
	}

	return mergo.MergeWithOverwrite(c, conf)
}
