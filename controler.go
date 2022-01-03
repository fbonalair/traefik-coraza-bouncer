package bouncer

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"net/http"
)

const (
	clientIpHeader = "X-Real-Ip"
	healthCheckIp  = "127.0.0.1"
)

var (
	requestProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_coraza_bouncer_processed_request_total",
		Help: "The total number of processed requests",
	})
)

/**
Call Coraza WAF
*/
func isRequestAuthorized(c *gin.Context, realIP string) (bool, error) {
	// TODO Coraza
	// Authorization logic
	return true, nil
}

/*
	Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	requestProcessed.Inc()
	// Getting and verifying ip from header
	realIP := c.Request.Header.Get(clientIpHeader)

	isAuthorized, err := isRequestAuthorized(c, realIP)
	if err != nil {
		log.Warn().Err(err).Msgf("An error occurred while checking request %q", realIP)
		c.String(http.StatusForbidden, "Forbidden")
	} else if !isAuthorized {
		c.String(http.StatusForbidden, "Forbidden")
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Route to check bouncer WAF capability. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	isHealthy, err := isRequestAuthorized(c, healthCheckIp)
	if err != nil || !isHealthy {
		log.Warn().Err(err).Msg("The health check did not pass...")
		c.Status(http.StatusForbidden)
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Simple route responding pong to every request. Mainly use for Kubernetes liveliness probe
*/
func Ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func Metrics(c *gin.Context) {
	handler := promhttp.Handler()
	handler.ServeHTTP(c.Writer, c.Request)
}
