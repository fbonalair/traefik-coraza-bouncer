package main

import (
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"net/http"
)

type WafWrapper struct {
	waf     *coraza.Waf
	parser  *seclang.Parser
	Metrics struct {
		SecrulesAmount     prometheus.Gauge
		RequestProcessed   prometheus.Counter
		RequestInterrupted prometheus.Counter
	}
}

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

/**
Initialize coraza module
*/
func NewWafWrapper(registry *prometheus.Registry) (wrapper *WafWrapper, err error) {
	wrapper = &WafWrapper{}
	// First we initialize our waf and our seclang parser
	wrapper.waf = coraza.NewWaf()
	wrapper.parser, err = seclang.NewParser(wrapper.waf)
	if err != nil {
		return
	}

	// Then we start our custom metrics
	wrapper.Metrics.SecrulesAmount = promauto.With(registry).NewGauge(prometheus.GaugeOpts{
		Name: "traefik_coraza_bouncer_processed_secrules_amount",
		Help: "The current number of processed sec rules",
	})
	wrapper.Metrics.RequestInterrupted = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "traefik_coraza_bouncer_interrupted_request_total",
		Help: "The total number of interrupted requests",
	})

	return
}

func (waf WafWrapper) parseRulesFromString(value string) (err error) {
	if err = waf.parser.FromString(value); err != nil {
		log.Fatal().Err(err).Msgf("error while parsing rule(s) from value %s", value)
		return
	}
	waf.Metrics.SecrulesAmount.Set(float64(waf.waf.Rules.Count()))
	return
}

func (waf WafWrapper) parseRulesFromFile(path string) (err error) {
	if err = waf.parser.FromFile(path); err != nil {
		log.Fatal().Err(err).Msg("error while parsing rule(s) from rule file/directory")
		return
	}
	waf.Metrics.SecrulesAmount.Set(float64(waf.waf.Rules.Count()))
	return
}

func (waf WafWrapper) ProcessRequest(request RequestProperties) (it *types.Interruption) {
	// We create a transaction and assign some variables
	tx := waf.waf.NewTransaction()
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
	it = tx.ProcessRequestHeaders()
	if it != nil {
		waf.Metrics.RequestInterrupted.Inc()
		log.Info().Int("RuleID", it.RuleID).
			Str("Action", it.Action).
			Int("Status", it.Status).
			Str("Data", it.Data).
			Msgf("Transaction %q from request X was interrupted", tx.ID)
	} else {
		log.Debug().Msgf("Transaction %q from request X passed without interrupt", tx.ID)
	}
	return
}
