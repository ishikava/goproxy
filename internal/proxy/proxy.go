//Script name: Captcha Proxy.
//This script is designed to filter http flood and is built on interaction with nginx.
//Example of nginx configuration:
/*
geo $use_proxy {
    default 1;
    172.22.132.66/32 0;
    95.211.246.181/32 0;
    10.0.0.2 0;
}
server {
    listen 80;
    server_name server.name
    location / {
        proxy_set_header Recap_host warthunder.ru.dev;
        proxy_set_header Recap_scheme http;
        if ($proxy){
            proxy_pass http://10.0.0.2:8080;
        }
        try_files $uri @backend;
    }
}
*/
//All requests that came to nginx by default are proxy passed to Captcha Proxy. Captcha Proxy determines whether the client has a fingerprint session (Remote IP + salt)
//If not, a page with Google Recaptcha is shown to the client. In case of captcha successfully resolved, fingerprint session created and the client redirects to the URL from which he came.
//If the client already has a fingerprint, Captcha Proxy requests content from the backend and gives it to the client unchanged.
//In its turn, nginx can identify request from Captcha Proxy by geo IP and will serve content as well instead of proxy_pass

//For consistency nginx MUST set proxy_set_headers Recap_host and Recap_scheme , if not - all traffic will be redirected to default host from .config.yaml

package proxy

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"

	"gaijin/lib/error/trigger"
	"gaijin/lib/sensu"
	"gaijin/lib/stat"
	"gaijin/web/captcha_proxy/internal/config"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var (
	captchaApiError         *trigger.Trigger
	captchaResponseError    *trigger.Trigger
	sensuClient             *sensu.Client
	logger                  *logrus.Logger
	outputPage              bytes.Buffer
	templateParams          HtmlData
	proxy                   = httputil.ReverseProxy{}
	cfg                     config.Config
	captchaShown            stat.Counter
	contentProxying         stat.Counter
	captchaResolveRequested stat.Counter
	captchaSolved           stat.Counter
	captchaNotSolved        stat.Counter
)

type HtmlData struct {
	RecaptchaSrc        string
	RecaptchaBackground string
	RecaptchaPublicKey  string
	RecaptchaActionUrl  string
}

type CaptchaResponse struct {
	Success bool     `json:"success"`
	Errors  []string `json:"error-codes"`
}

//The main handler is key logic of the app.
//We check if client does have fingerprint session and decide show captcha page or proxying requested content
func Handler(c *gin.Context) {

	clientIp := GetIpAddress(c.Request.RemoteAddr)
	session := sessions.Default(c)

	sessionFingerprint, ok := session.Get("fingerprint").(string)
	clientFingerprint := getFingerprintHash(clientIp, cfg.Salt)

	//check fingerprint
	if sessionFingerprint != clientFingerprint || !ok {
		//First look if request is from captcha page
		//If Uri contains /recaptchaActionUrl/ it means explicit POST request from recaptcha page, to resolve Google Recaptcha challenge
		//Call captchaResolveRequest
		if c.Param("name") == cfg.Recaptcha.ActionUrl {
			captchaResolveRequest(c, clientIp, session, clientFingerprint)
			return
		}

		//save scheme, host and uri in session, to be able to redirect client correctly
		SetSessionHostParams(c, session)

		//get host and scheme here just for logging
		host := getHostFromSession(session)
		scheme := getSchemeFromSession(session)
		uri := getUriFromSession(session)

		//Show buffered html template with captcha
		c.Header("Cache-Control", "no-cache, must-revalidate")
		c.Header("Content-Type", "text/html; charset=UTF-8")
		c.Writer.Write(outputPage.Bytes())

		if err := captchaShown.Increase(1); err != nil {
			logger.WithError(err).Fatal("can't increase stat.Counter")
		} else {
			logger.WithFields(logrus.Fields{
				"IP":                 clientIp,
				"ReturnUrl":          scheme + "://" + host + uri,
				"clientFingerprint":  clientFingerprint,
				"sessionFingerprint": sessionFingerprint,
			}).Info("Captcha shown to : ")
		}

		return

	} else {
		//we need to set correct scheme and host to proxying traffic
		host := getHostFromSession(session)
		scheme := getSchemeFromSession(session)

		//proxying traffic
		proxy.Director = func(request *http.Request) {
			request.Host = host
			request.URL.Scheme = scheme
			request.URL.Host = host
		}
		proxy.ServeHTTP(c.Writer, c.Request)

		if err := contentProxying.Increase(1); err != nil {
			logger.WithError(err).Fatal("can't increase stat.Counter")
		} else {
			logger.WithFields(logrus.Fields{
				"IP":                 clientIp,
				"Url":                scheme + "://" + host + c.Request.RequestURI,
				"clientFingerprint":  clientFingerprint,
				"sessionFingerprint": sessionFingerprint,
			}).Info("Content proxying to : ")
		}

		return

	}

}

//Make POST request to Google siteverify API with received token
func captchaResolveRequest(c *gin.Context, ip string, session sessions.Session, clientFingerprint string) {

	host := getHostFromSession(session)
	scheme := getSchemeFromSession(session)
	uri := getUriFromSession(session)

	returnUrl := scheme + "://" + host + uri

	token := c.PostForm("g-recaptcha-response")
	result := CaptchaResponse{}

	response, err := http.PostForm(cfg.Recaptcha.Api,
		url.Values{
			"secret":   {cfg.Recaptcha.PrivateKey},
			"response": {token},
			"remoteip": {ip},
		})

	if err != nil {
		//increase captcha Api error counter
		captchaApiError.Change(1)
		logger.Info(cfg.Recaptcha.Api + " does not respond")
	} else {
		//decrease captcha Api error counter
		if captchaApiError.Get() > 0 {
			captchaApiError.Change(-1)
		}

		if err := captchaResolveRequested.Increase(1); err != nil {
			logger.WithError(err).Fatal("can't increase stat.Counter")
		} else {
			logger.WithFields(logrus.Fields{
				"IP":        ip,
				"ReturnUrl": returnUrl,
			}).Info("Google siteverify requested : ")
		}
	}

	body, err := ioutil.ReadAll(response.Body)
	jsonError := json.Unmarshal(body, &result)
	defer response.Body.Close()

	if err != nil || jsonError != nil {
		//increase captcha Response error counter
		captchaResponseError.Change(1)
		logger.Info("Bad response from " + cfg.Recaptcha.Api)
	} else {
		//decrease captcha Response error counter
		if captchaResponseError.Get() > 0 {
			captchaResponseError.Change(-1)
		}
	}

	if result.Success == true {
		//Captcha solved and passed, set valid session fingerprint
		session.Set("fingerprint", clientFingerprint)
		session.Save()

		if err := captchaSolved.Increase(1); err != nil {
			logger.WithError(err).Fatal("can't increase stat.Counter")
		} else {
			logger.WithFields(logrus.Fields{
				"IP":        ip,
				"ReturnUrl": returnUrl,
			}).Info("Captcha successfully solved : ")
		}
	} else {
		//Captcha not solved
		if err := captchaNotSolved.Increase(1); err != nil {
			logger.WithError(err).Fatal("can't increase stat.Counter")
		} else {
			logger.WithFields(logrus.Fields{
				"IP":        ip,
				"ReturnUrl": returnUrl,
				"Errors":    strings.Join(result.Errors, "|"),
			}).Info("Captcha NOT solved : ")
		}
	}

	//Now redirect client back to returnUrl.
	c.Redirect(302, returnUrl)
	return

}

func MustLoadConfig(cfg *config.Config) {

	logger = cfg.Log.Logger()

	//template
	tplStr, err := ioutil.ReadFile(filepath.Join(cfg.BaseUrl, "templates/recaptcha.html"))
	if err != nil {
		logger.WithError(err).Fatal("can't read HTML template")
	}
	tmpl := template.New("recaptcha")
	tmpl, err = tmpl.Parse(string(tplStr))
	if err != nil {
		logger.WithError(err).Fatal("can't parse HTML template")
	}
	templateParams.RecaptchaActionUrl = cfg.Recaptcha.ActionUrl
	templateParams.RecaptchaBackground = cfg.Recaptcha.Background
	templateParams.RecaptchaPublicKey = cfg.Recaptcha.PublicKey
	templateParams.RecaptchaSrc = cfg.Recaptcha.Src
	tmpl.Execute(&outputPage, templateParams)

	//stats
	stat.SetHost(cfg.Stat.Host)
	stat.SetPort(uint16(cfg.Stat.Port))
	receiver := stat.NewReceiver()
	receiver.SetTags(
		stat.NewTagSet().
			Set("tag1", "value").
			Set("tag2", "value"))

	receiver.MustConnect()
	measure := receiver.NewMeasurement("captcha-proxy")

	captchaShown = measure.NewCounter("captcha-shown")
	contentProxying = measure.NewCounter("content-proxying")
	captchaResolveRequested = measure.NewCounter("captcha-resolve-requested")
	captchaSolved = measure.NewCounter("captcha-solved")
	captchaNotSolved = measure.NewCounter("captcha-not-solved")

	//sensu client with error counters
	sensuClient, _ = sensu.NewClient(cfg.Sensu.Address)

	captchaApiError = trigger.New(captchaApiErrorCb, captchaApiOkCb)
	captchaApiError.SafeZone = 10
	captchaApiError.MaxAllowed = 100
	captchaApiError.Run()

	captchaResponseError = trigger.New(captchaResponseErrorCb, captchaResponseBodyOkCb)
	captchaResponseError.SafeZone = 10
	captchaResponseError.MaxAllowed = 100
	captchaResponseError.Run()

	//switch off gin debug logger
	if !config.Cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
}
