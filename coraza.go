package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"net/http"
	"path/filepath"
)

/*
	Data representing a request for Coraza
*/
type RequestProperties struct {
	ClientIp   string
	ClientPort int
	ServerIp   string
	ServerPort int
	Headers    http.Header
}

var (
	waf     *coraza.Waf
	parser  *seclang.Parser
	initErr error

	shouldDlRecommended       = configs.Values.SecRules.Recommended
	shouldDlOwasp             = configs.Values.SecRules.Owasp
	bouncerSecCustomRulesPath = configs.Values.SecRules.CustomPath
	bouncerSecRule            = configs.Values.SecRules.CustomRule

	secrulesAmount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "traefik_coraza_bouncer_processed_secrules_amount",
		Help: "The current number of processed sec rules",
	})
	requestInterrupted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_coraza_bouncer_interrupted_request_total",
		Help: "The total number of interrupted requests",
	})
)

/**
Initialize coraza module
*/
func init() {
	// First we initialize our waf and our seclang parser
	waf = coraza.NewWaf()
	parser, initErr = seclang.NewParser(waf)
	if initErr != nil {
		log.Fatal().Err(initErr).Msg("error while initializing seclang parser")
	}
}

func ParseSecRules() {
	// Fetching and adding coraza recommended configuration
	if shouldDlRecommended {
		success := DownloadCorazaRecommendation()
		if !success {
			log.Fatal().Msgf("Server failed to download recommended Coraza configuration")
		}
		if err := parser.FromFile(CorazaConfPath); err != nil {
			log.Fatal().Err(err).Msgf("error loading Coraza recommended configuration")
		}
	}

	// Fetching and parsing OWASP core Ruleset
	if shouldDlOwasp {
		success := DownloadOwaspCoreRules()
		if !success {
			log.Fatal().Msgf("Server failed to download OWASP rulesec")
		}
		owaspPath := filepath.Join(OwaspConfExamplePath, "*.conf")
		if initErr := parser.FromFile(owaspPath); initErr != nil {
			log.Fatal().Err(initErr).Msgf("error while loading Owasp core ruleset")
		}
	}
	// Now we parse our custom rules
	if initErr := parser.FromString(bouncerSecRule); initErr != nil {
		log.Fatal().Err(initErr).Msgf("error while parsing rule %s", bouncerSecRule)
	}
	if initErr := parser.FromFile(bouncerSecCustomRulesPath); initErr != nil {
		log.Fatal().Err(initErr).Msg("error while parsing rule(s) from rule file/directory")
	}
	secrulesAmount.Set(float64(waf.Rules.Count()))
}

func ProcessRequest(request RequestProperties) *types.Interruption {
	// We create a transaction and assign some variables
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection(request.ClientIp, request.ServerPort, request.ServerIp, request.ServerPort)

	// Adding request headers
	// Loop over header names
	for name, values := range request.Headers {
		// Loop over all values for the name.
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	// Finally, we process the request headers phase, which may return an interruption
	it := tx.ProcessRequestHeaders()
	if it != nil {
		requestInterrupted.Inc()
		log.Info().Int("RuleID", it.RuleID).
			Str("Action", it.Action).
			Int("Status", it.Status).
			Str("Data", it.Data).
			Msgf("Transaction %q from request X was interrupted", tx.ID)
	} else {
		log.Debug().Msgf("Transaction %q from request X passed without interrupt", tx.ID)
	}
	return it
}
