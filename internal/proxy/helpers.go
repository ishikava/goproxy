package proxy

import (
	"crypto/sha1"
	"fmt"
	"io"
	"regexp"

	"gaijin/lib/strings/randomstr"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

//get "scheme" field value from session, if value is empty, get default from config
func getSchemeFromSession(session sessions.Session) string {
	scheme, ok := session.Get("scheme").(string)
	if !ok {
		scheme = cfg.DefaultScheme
	}
	return scheme
}

//get "host" field value from session, if value is empty, get default from config
func getHostFromSession(session sessions.Session) string {
	host, ok := session.Get("host").(string)
	if !ok {
		host = cfg.DefaultHost
	}
	return host
}

//get "uri" field value from session, if value is empty, get default string "/"
func getUriFromSession(session sessions.Session) string {
	uri, ok := session.Get("uri").(string)
	if !ok {
		uri = "/"
	}
	return uri
}

//saves scheme, host and uri in session
func SetSessionHostParams(c *gin.Context, session sessions.Session) {

	//IMPORTANT! This headers must be set by nginx.
	//For example:
	//proxy_set_header Recap_host warthunder.ru.dev;
	//proxy_set_header Recap_scheme http;
	//It needed for correct client redirection. If not set, default values from config will be used
	host := c.Request.Header.Get("Recap_host")
	if host == "" {
		host = cfg.DefaultHost
	}
	scheme := c.Request.Header.Get("Recap_scheme")
	if scheme == "" {
		scheme = cfg.DefaultScheme
	}

	session.Set("host", host)
	session.Set("scheme", scheme)
	session.Set("uri", c.Request.RequestURI)
	session.Save()

}

//returns hash sum of concatenated IP and salt
func getFingerprintHash(ip string, salt string) string {
	fingerprintHash := sha1.New()
	_, err := io.WriteString(fingerprintHash, ip+salt)
	if err != nil {
		logger.Panic(err)
	}
	return fmt.Sprint(fingerprintHash.Sum(nil))
}

//Returns correct IP address, or random string
func GetIpAddress(ip string) string {
	regex := regexp.MustCompile(`\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(:\d{0,5})?`)
	match := regex.MatchString(ip)
	if !match {
		return randomstr.Generate(10)
	}
	return ip
}

//alerting sensu about too many captcha Api errors
func captchaApiErrorCb(c, min, max int) {
	msg := fmt.Sprintf("Captcha Api Errors Counter too big: %d vs allowed %d", c, max)
	sensuClient.Critical("captcha_proxy", msg)
	logger.Println(msg)
}

//alerting sensu about captcha Api errors is back to normal
func captchaApiOkCb(c, min, max int) {
	msg := fmt.Sprintf("Captcha Api Errors Counter is back to normal: %d", c)
	sensuClient.Critical("captcha_proxy", msg)
	logger.Println(msg)
}

//alerting sensu about too many captcha Body errors
func captchaResponseErrorCb(c, min, max int) {
	msg := fmt.Sprintf("Captcha Body Errors Counter too big: %d vs allowed %d", c, max)
	sensuClient.Critical("captcha_proxy", msg)
	logger.Println(msg)
}

//alerting sensu about captcha Body errors is back to normal
func captchaResponseBodyOkCb(c, min, max int) {
	msg := fmt.Sprintf("Captcha Body Errors Counter is back to normal: %d", c)
	sensuClient.Critical("captcha_proxy", msg)
	logger.Println(msg)
}
