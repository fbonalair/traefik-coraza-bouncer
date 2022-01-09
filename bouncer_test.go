package main

import (
	"github.com/spf13/viper"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	beforeEach()
	code := m.Run()
	afterEach()
	os.Exit(code)
}

func beforeEach() {}

func afterEach() {
	err := os.RemoveAll("./test/rules/downloaded")
	if err != nil {
		log.Println("Error while cleaning rules download path")
	}
}

func TestPing(t *testing.T) {
	router := CreateRouter("./test", viper.New()).router
	w := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/v1/ping", nil)
	router.ServeHTTP(w, req)

	assert.NoError(t, err)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "pong", w.Body.String())

}

func TestHealthz(t *testing.T) {
	router := CreateRouter("./test", viper.New()).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestMetrics(t *testing.T) {
	router := CreateRouter("./test", viper.New()).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/metrics", nil)
	router.ServeHTTP(w, req)
	response := w.Body.String()

	assert.Equal(t, 200, w.Code)
	//assert.Contains(t, response, "go_info") // FIXME add back general metrics
	assert.Contains(t, response, "traefik_coraza_bouncer_processed_request_total")
	assert.Contains(t, response, "traefik_coraza_bouncer_processed_secrules_amount")
	assert.Contains(t, response, "traefik_coraza_bouncer_interrupted_request_total")
}

func TestForwardAuth(t *testing.T) {
	t.Run("Simple Request", simpleRequest)
	t.Run("Custom rules", FACustomRule)
	t.Run("Custom path rules", FABouncerSecRulesPath)
	t.Run("Coraza recommended", FACorazaRecommended)
	t.Run("OWASP recommended", FAOwaspRecommended)
}

func simpleRequest(t *testing.T) {
	server := CreateRouter("./test", viper.New())
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "1.1.1.1")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, server.waf.waf.Rules.Count(), 0)

}

func FACustomRule(t *testing.T) {
	viperConfig := viper.New()
	viperConfig.Set("SEC_RULES.CUSTOM_RULE", "SecRule REMOTE_ADDR \"@rx 2.2.2.2\" \"id:1,phase:1,deny,status:403\"")
	router := CreateRouter("./test", viperConfig).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "2.2.2.2")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func FABouncerSecRulesPath(t *testing.T) {
	viperConfig := viper.New()
	viperConfig.Set("SEC_RULES.CUSTOM_PATH", "./test/rules/custom/*")
	router := CreateRouter("./test", viperConfig).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "3.3.3.3")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func FACorazaRecommended(t *testing.T) {
	viperConfig := viper.New()
	viperConfig.Set("SEC_RULES.RECOMMENDED", true)
	server := CreateRouter("./test", viperConfig)
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "2.2.2.2")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Greater(t, server.waf.waf.Rules.Count(), 0)
}

func FAOwaspRecommended(t *testing.T) {
	viperConfig := viper.New()
	viperConfig.Set("SEC_RULES.OWASP", true)
	viperConfig.Set("SEC_RULES.OWASP_SHA", "63aa8ee3f3c9cb23f5639dd235bac1fa1bc64264")
	server := CreateRouter("./test", viperConfig)
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "2.2.2.2")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	server.router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Greater(t, server.waf.waf.Rules.Count(), 0)
}
