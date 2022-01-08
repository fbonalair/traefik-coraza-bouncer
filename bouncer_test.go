package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
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

func afterEach() {}

func mainTest(viper *viper.Viper) *Server {
	// FIXME factorise this test main and normal main
	setupLogger()
	registry := prometheus.NewRegistry()

	configPath := "./test"
	viper.Set("SEC_RULES.DOWNLOADED_PATH", "./test/rules/downloaded")
	viper.Set("SEC_RULES.RECOMMENDED", false)
	viper.Set("SEC_RULES.OWASP", false)
	config := configs.ParseConfig(configPath, viper)

	waf, err := NewWafWrapper(registry)
	if err != nil {
		log.Fatal().Err(err).Msg("error while initializing seclang parser")
	}

	err = fetchAndParseSecRules(config, waf)
	if err != nil {
		log.Fatal().Err(err).Msg("error while fetching configuration file(s)")
	}

	return NewServer(waf, registry, config.HealthzRoute)
}

func TestPing(t *testing.T) {
	server := mainTest(viper.New())

	w := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/v1/ping", nil)
	server.router.ServeHTTP(w, req)

	assert.NoError(t, err)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "pong", w.Body.String())

}

func TestHealthz(t *testing.T) {
	router := mainTest(viper.New()).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestMetrics(t *testing.T) {
	router := mainTest(viper.New()).router
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
	router := mainTest(viper.New()).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "1.1.1.1")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestCustomRules(t *testing.T) {
	viperConfig := viper.New()
	viperConfig.Set("SEC_RULES.CUSTOM_RULE", "SecRule REMOTE_ADDR \"@rx 2.2.2.2\" \"id:1,phase:1,deny,status:403\"")
	router := mainTest(viperConfig).router
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "2.2.2.2")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func TestForwardAuthBouncerSecRulesPath(t *testing.T) {
	router := mainTest(viper.New()).router
	w := httptest.NewRecorder()

	//configs.Values.SecRules.CustomPath = "./test/rules/custom/*"
	//ParseSecRules()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.Header.Add("X-Real-Ip", "3.3.3.3")
	req.Header.Add("X-Forwarded-Host", "127.0.0.1")
	req.Header.Add("X-Forwarded-Port", "8080")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}
