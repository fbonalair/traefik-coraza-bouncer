package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

func main() {
	configPath := os.Getenv("BOUNCER_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/bouncer/"
	}
	viperConfig := viper.New()

	router := CreateRouter(configPath, viperConfig)
	err := router.Start()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
	}
}

func CreateRouter(configPath string, viper *viper.Viper) *Server {
	setupLogger()
	registry := prometheus.NewRegistry()
	config := configs.ParseConfig(configPath, viper)

	waf, err := NewWafWrapper(registry)
	if err != nil {
		log.Fatal().Err(err).Msg("error while initializing seclang parser")
	}

	err = fetchAndParseSecRules(config, waf)
	if err != nil {
		log.Fatal().Err(err).Msg("error while fetching configuration file(s)")
	}

	router := NewServer(waf, registry, config.HealthzRoute)
	return router
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

func fetchAndParseSecRules(config configs.Config, waf *WafWrapper) (err error) {
	var dl *Downloader
	if config.Recommended || config.Owasp {
		dl, err = NewDownloader(config.SecRules)
	}
	// Fetching and adding coraza recommended configuration
	if config.Recommended {
		success := dl.DownloadCorazaRecommendation()
		if !success {
			log.Fatal().Msgf("Server failed to download recommended Coraza configuration")
		}
		if err := waf.parseRulesFromFile(dl.corazaConfPath); err != nil {
			log.Fatal().Err(err).Msgf("Error loading Coraza recommended configuration")
		}
	}

	// Fetching and parsing OWASP core Ruleset
	if config.Owasp {
		success := dl.DownloadOwaspCoreRules()
		if !success {
			log.Fatal().Msgf("Server failed to download OWASP rulesec")
		}
		owaspPath := filepath.Join(config.DownloadedPath, "*.conf")
		if initErr := waf.parseRulesFromFile(owaspPath); initErr != nil {
			log.Fatal().Err(initErr).Msgf("error while loading Owasp core ruleset")
		}
	}
	// Now we parse our custom rules
	if initErr := waf.parseRulesFromString(config.CustomRule); initErr != nil {
		log.Fatal().Err(initErr).Msgf("error while parsing rule %s", config.CustomRule)
	}
	if initErr := waf.parseRulesFromFile(config.CustomPath); initErr != nil {
		log.Fatal().Err(initErr).Msgf("error while parsing rule(s) from rule file/directory %s", config.CustomPath)
	}
	return
}
