package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
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

func beforeEach() {
	configs.Values.SecRules.Owasp = false
	configs.Values.SecRules.Recommended = false
	configs.Values.SecRules.CustomRule = ""
	configs.Values.SecRules.CustomPath = "./test/rules/empty/*.conf"
}

func afterEach() {}

func mainTest() *Server {
	setupLogger()
	registry := prometheus.NewRegistry()

	waf, err := NewWafWrapper(registry)
	if err != nil {
		log.Fatal().Err(err).Msg("error while initializing seclang parser")
	}

	return NewServer(waf, registry)
	//err = server.Start()
	//if err != nil {
	//	log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
	//}
}

func TestPing(t *testing.T) {
	server := mainTest()

	w := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/v1/ping", nil)
	server.router.ServeHTTP(w, req)

	assert.NoError(t, err)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "pong", w.Body.String())

}

func TestHealthz(t *testing.T) {
	router := mainTest().router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestMetrics(t *testing.T) {
	router := mainTest().router
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
	router := mainTest().router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "1.1.1.1")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestCustomRules(t *testing.T) {
	router := mainTest().router
	w := httptest.NewRecorder()

	configs.Values.SecRules.CustomRule = "SecRule REMOTE_ADDR \"@rx 2.2.2.2\" \"id:1,phase:1,deny,status:403\""
	//ParseSecRules()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "2.2.2.2")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func TestForwardAuthBouncerSecRulesPath(t *testing.T) {
	router := mainTest().router
	w := httptest.NewRecorder()

	configs.Values.SecRules.CustomPath = "./test/rules/custom/*"
	//ParseSecRules()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "3.3.3.3")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}
