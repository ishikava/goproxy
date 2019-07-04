package proxy_test

import (
	"testing"

	"gaijin/web/captcha_proxy/internal/proxy"

	"github.com/stretchr/testify/assert"
)

func TestGetIpAddress(t *testing.T) {

	assert.Equal(t, "0.0.0.0", proxy.GetIpAddress("0.0.0.0"))
	assert.Equal(t, "255.255.255.255", proxy.GetIpAddress("255.255.255.255"))
	assert.Equal(t, "255.255.255.255:8080", proxy.GetIpAddress("255.255.255.255:8080"))

	assert.Equal(t, 10, len(proxy.GetIpAddress("")))
	assert.Equal(t, 10, len(proxy.GetIpAddress("xxx.xxx.xxx.xxx:xxxxx")))
}
