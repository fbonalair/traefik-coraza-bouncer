package main

import (
	"github.com/fbonalair/traefik-coraza-bouncer/configs"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"net/http"
	"strconv"
)

const (
	serverHostHeader = "X-Forwarded-Host"
	clientIpHeader   = "X-Real-Ip" // or X-Forwarded-For
	clientPortHeader = "X-Forwarded-Port"
)

var (
	healthClientIp   = configs.Values.HealthzRoute.ClientIp
	healthClientPort = configs.Values.HealthzRoute.ClientPort
	healthServerIp   = configs.Values.HealthzRoute.ServerIp
	healthServerPort = configs.Values.HealthzRoute.ServerPort

	clientPort = configs.Values.HealthzRoute.ServerPort

	requestProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "traefik_coraza_bouncer_processed_request_total",
		Help: "The total number of processed requests",
	})
)

/*
	Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	requestProcessed.Inc()

	// Parsing int
	serverPort, err := strconv.Atoi(c.Request.Header.Get(clientPortHeader))
	if err != nil {
		log.Warn().Err(err).Msg("Can't convert server port to int")
		c.String(http.StatusForbidden, "Forbidden")
	}

	request := RequestProperties{
		ClientIp:   c.Request.Header.Get(clientIpHeader),
		ClientPort: clientPort,
		ServerIp:   c.Request.Header.Get(serverHostHeader),
		ServerPort: serverPort,
		Headers:    c.Request.Header.Clone(),
	}
	request.Headers.Del(clientIpHeader)
	request.Headers.Del(clientPortHeader)
	request.Headers.Del(serverHostHeader)

	interrupt := ProcessRequest(request)
	if interrupt != nil {
		c.String(interrupt.Status, "")
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Route to check bouncer WAF capability. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	request := RequestProperties{
		ClientIp:   healthClientIp,
		ClientPort: healthClientPort,
		ServerIp:   healthServerIp,
		ServerPort: healthServerPort,
	}
	interrupt := ProcessRequest(request)
	if interrupt != nil {
		c.String(interrupt.Status, "")
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
