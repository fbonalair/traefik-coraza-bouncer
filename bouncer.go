package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/coraza"
	"github.com/fbonalair/traefik-coraza-bouncer/downloader"
	"github.com/fbonalair/traefik-coraza-bouncer/utils"
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"path/filepath"
)

var (
	shouldDlRecommended = utils.GetOptionalEnv(coraza.BouncerSecRulesRecommended, "true")
	shouldDlOwasp       = utils.GetOptionalEnv(coraza.BouncerSecRulesOwasp, "true")
)

func main() {
	// FIXME through back errors instead of bool
	if shouldDlRecommended == "true" {
		success := downloader.DownloadCorazaRecommendation()
		if !success {
			log.Fatal().Msgf("Server failed to download recommended Coraza configuration")
		}
		if err := coraza.Parser.FromFile(downloader.CorazaConfPath); err != nil {
			log.Fatal().Err(err).Msgf("error loading Coraza recommended configuration")
		}
	}
	if shouldDlOwasp == "true" {
		success := downloader.DownloadOwaspCoreRules()
		if !success {
			log.Fatal().Msgf("Server failed to download OWASP rulesec")
		}
		owaspPath := filepath.Join(downloader.OwaspConfExamplePath, "*.conf")
		if initErr := coraza.Parser.FromFile(owaspPath); initErr != nil {
			log.Fatal().Err(initErr).Msgf("error while loading Owasp core ruleset")
		}
	}
	coraza.ParseSecrules()
	router := setupRouter()
	err := router.Run()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
		return
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

	// TODO set proxy rules https://pkg.go.dev/github.com/gin-gonic/gin#readme-don-t-trust-all-proxies
	// router.SetTrustedProxies([]string{"192.168.1.2"})

	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	router.GET("/api/v1/ping", Ping)
	router.GET("/api/v1/healthz", Healthz)
	router.GET("/api/v1/forwardAuth", ForwardAuth)
	router.GET("/api/v1/metrics", Metrics)
	return router
}
