package coraza

import (
	"github.com/fbonalair/traefik-coraza-bouncer/utils"
	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/types"
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

const (
	BouncerSecRules            = "BOUNCER_SEC_RULES"
	BouncerSecRulesPath        = "BOUNCER_SEC_RULES_PATH"
	BouncerSecRulesPathDefault = "/etc/bouncer/rules/"
	BouncerSecRulesOwasp       = "BOUNCER_SEC_RULES_OWASP"
	BouncerSecRulesRecommended = "BOUNCER_SEC_RULES_RECOMMENDED"
)

var (
	waf     *coraza.Waf
	parser  *seclang.Parser
	initErr error
)

/**
Initialize coraza module
*/
func init() {
	// First we initialize our waf and our seclang parser
	waf = coraza.NewWaf()
}

func ParseSecrules() {
	parser, initErr = seclang.NewParser(waf)
	if initErr != nil {
		log.Fatal().Err(initErr).Msg("error while initializing seclang parser")
	}

	// TODO adding rules
	// Now we parse our rules
	bouncerSecRules := utils.GetOptionalEnv(BouncerSecRules, "")
	bouncerSecRulesDir := utils.GetOptionalEnv(BouncerSecRulesPath, BouncerSecRulesPathDefault)
	bouncerSecRulesPath := filepath.Join(bouncerSecRulesDir, "*.conf")

	if initErr := parser.FromString(bouncerSecRules); initErr != nil {
		log.Fatal().Err(initErr).Msgf("error while parsing rule %s", bouncerSecRules)
	}
	// TODO owasp example should be first to be read
	if initErr := parser.FromFile(bouncerSecRulesPath); initErr != nil {
		log.Fatal().Err(initErr).Msg("error while parsing rule(s) from rule file/directory")
	}
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
		log.Info().Int("RuleID", it.RuleID).
			Str("Action", it.Action).
			Int("Status", it.Status).
			Str("Data", it.Data).
			Msgf("Transaction %q from request X was interrupted", tx.ID) // TODO add link to request in log
	} else {
		// TODO add details
		log.Debug().Msgf("Transaction %q from request X passed without interrupt", tx.ID)
	}
	return it
}
