package config

import (
	"fmt"
	"os"

	"gaijin/lib/config"
)

var Cfg Config

type Config struct {
	config.DefaultConfig
	BaseUrl          string `valid:"required"`
	DefaultInterface string `cfg:"flag"`
	EncryptionKey    string `valid:"required"`
	Salt             string `valid:"required"`
	DefaultHost      string `valid:"required"`
	DefaultScheme    string `valid:"required"`
	Recaptcha        struct {
		PublicKey  string `valid:"required"`
		PrivateKey string `valid:"required"`
		Src        string `valid:"required, url"`
		Api        string `valid:"required, url"`
		ActionUrl  string `valid:"required"`
		Background string `valid:"required"`
	}
	Stat struct {
		Host string `valid:"required, host"`
		Port int    `valid:"required, port"`
	}
	Debug bool
}

func MustLoadConfig() {
	parser := config.New()
	if err := parser.Parse(&Cfg); err != nil {
		fmt.Println("Config init error: ", err)
		os.Exit(1)
	}
}
