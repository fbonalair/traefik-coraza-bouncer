package main

import (
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {
	setupLogger()
	registry := prometheus.NewRegistry()

	waf, err := NewWafWrapper(registry)
	if err != nil {
		log.Fatal().Err(err).Msg("error while initializing seclang parser")
	}

	router := NewServer(waf, registry)
	err = router.Start()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
	}
}

func setupLogger() {
	// logger framework
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if gin.IsDebugging() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				NoColor:    false,
				TimeFormat: zerolog.TimeFieldFormat,
			},
		)
	}
}

func setupRouter() *gin.Engine {
	// logger framework
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if gin.IsDebugging() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				NoColor:    false,
				TimeFormat: zerolog.TimeFieldFormat,
			},
		)
	}

	// Web framework
	router := gin.New()
	router.SetTrustedProxies(nil)
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	//router.GET("/api/v1/ping", Ping)
	//router.GET("/api/v1/healthz", Healthz)
	//router.GET("/api/v1/forwardAuth", ForwardAuth)
	//router.GET("/api/v1/metrics", Metrics)
	return router
}
