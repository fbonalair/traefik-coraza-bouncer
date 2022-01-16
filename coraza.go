package main

import (
	"fmt"
	_ "github.com/jptosso/coraza-libinjection"
	_ "github.com/jptosso/coraza-pcre"
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
	Request    *http.Request
}

// NewWafWrapper Initialize coraza module
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

func (waf WafWrapper) parseRulesFromString(value string) error {
	if err := waf.parser.FromString(value); err != nil {
		return fmt.Errorf("error while parsing rule(s) from value %s : %s", value, err.Error())
	}
	waf.Metrics.SecrulesAmount.Set(float64(waf.waf.Rules.Count()))
	return nil
}

func (waf WafWrapper) parseRulesFromFile(path string) error {
	if err := waf.parser.FromFile(path); err != nil {
		return fmt.Errorf("error while parsing rule(s) from rule file/directory : %s", err.Error())
	}
	waf.Metrics.SecrulesAmount.Set(float64(waf.waf.Rules.Count()))
	return nil
}

func (waf WafWrapper) ProcessRequest(request RequestProperties) (it *types.Interruption, err error) {
	method := request.Request.Header.Get("X-Forwarded-Method")
	uri := request.Request.Header.Get("X-Forwarded-Uri")
	proto := "HTTP/1.1"

	// We create a transaction and assign some variables
	tx := waf.waf.NewTransaction()
	defer func() {
		// A transaction must be logged and taken back to the sync pool
		tx.ProcessLogging()
		err := tx.Clean()
		if err != nil {
			log.Warn().Err(err).Msgf("Error while cleaning up after transaction %q", tx.ID)
		}
	}()
	tx.ProcessConnection(request.ClientIp, request.ServerPort, request.ServerIp, request.ServerPort)
	tx.ProcessURI(uri, method, proto)

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
		log.Debug().Msgf("Transaction %q passed request header without interrupt", tx.ID)
	}

	it, err = tx.ProcessRequest(request.Request)
	if err != nil {
		return
	}
	if it != nil {
		waf.Metrics.RequestInterrupted.Inc()
		log.Info().Int("RuleID", it.RuleID).
			Str("Action", it.Action).
			Int("Status", it.Status).
			Str("Data", it.Data).
			Msgf("Transaction %q from request was interrupted", tx.ID)

		if it.Status < 299 {
			log.Warn().Msgf("Interrupt recommended status %d < 299, defaulting to 403", it.Status)
			it.Status = 403
		}
	} else {
		log.Debug().Msgf("Transaction %q passed request without interrupt", tx.ID)
	}

	return
}
