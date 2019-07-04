//Script name: Captcha Proxy.
//This script is designed to filter http flood and is built on interaction with nginx.
//Read description in proxy.go
package main

import (
	"gaijin/lib/log/gin-logger"
	"gaijin/web/captcha_proxy/internal/config"
	"gaijin/web/captcha_proxy/internal/proxy"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

var (
	cfg = &config.Cfg
)

//simple gin-gonic web server
func main() {

	config.MustLoadConfig()
	proxy.MustLoadConfig(cfg)

	logger := cfg.Log.Logger()

	store := sessions.NewCookieStore([]byte(cfg.EncryptionKey))

	router := gin.New()
	router.Use(gin_logger.New(logger.WithField("prefix", "gin")))
	router.Use(gin.Recovery())

	session := sessions.Sessions("recap_session", store)
	router.Use(session)

	router.Any("/*name", proxy.Handler)

	router.Run(cfg.DefaultInterface)

}
