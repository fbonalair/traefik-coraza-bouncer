package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

func main() {
	setupLogger()
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
	registry := prometheus.NewRegistry()
	config := ParseConfig(configPath, viper)

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

func fetchAndParseSecRules(config Config, waf *WafWrapper) error {
	var dl *Downloader
	if config.Recommended || config.Owasp {
		dl = NewDownloader(config.SecRules)
	}
	// Fetching and adding coraza recommended configuration
	if config.Recommended {
		err := dl.DownloadCorazaRecommendation()
		if err != nil {
			return fmt.Errorf("server failed to download recommended Coraza configuration: %s", err.Error())
		}
		if err := waf.parseRulesFromFile(dl.corazaConfPath); err != nil {
			return fmt.Errorf("server failed to load recommended Coraza configuration: %s", err.Error())
		}
	}

	// Fetching and parsing OWASP core Ruleset
	if config.Owasp {
		owaspDlDir, err := dl.DownloadOwaspCoreRules()
		if err != nil {
			return fmt.Errorf("server failed to download OWASP rulesec: %s", err.Error())
		}
		owaspExampleFile := filepath.Join(config.DownloadedPath, config.OwaspUrlExampleFile)
		if err := waf.parseRulesFromFile(owaspExampleFile); err != nil {
			return fmt.Errorf("server failed to load OWASP example rulesec file: %s", err.Error())
		}
		owaspPath := filepath.Join(owaspDlDir, "*.conf")
		if err := waf.parseRulesFromFile(owaspPath); err != nil {
			return fmt.Errorf("server failed to load OWASP rulesec: %s", err.Error())
		}
	}
	// Now we parse our custom rules
	if err := waf.parseRulesFromString(config.CustomRule); err != nil {
		return fmt.Errorf("server failed to parse custom rulesec %s: %s", config.CustomRule, err.Error())
	}
	if err := waf.parseRulesFromFile(config.CustomPath); err != nil {
		return fmt.Errorf("server failed to parse rule(s) from rule file/directory %s : %s", config.CustomPath, err.Error())
	}
	return nil
}
