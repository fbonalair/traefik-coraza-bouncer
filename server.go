package main

import (
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"net/http"
	"strconv"
)

type Server struct {
	waf    *WafWrapper
	router *gin.Engine

	Metrics struct {
		registry         *prometheus.Registry
		requestProcessed prometheus.Counter
	}
	config HealthzRoute
}

const (
	serverHostHeader = "X-Forwarded-Host"
	clientIpHeader   = "X-Real-Ip" // or X-Forwarded-For
	clientPortHeader = "X-Forwarded-Port"
)

func NewServer(waf *WafWrapper, registry *prometheus.Registry, config HealthzRoute) (server *Server) {
	server = &Server{
		waf:    waf,
		config: config,
	}
	server.Metrics.registry = registry

	// Web framework
	router := gin.New()
	router.SetTrustedProxies(nil)
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))

	// Add routes
	router.GET("/api/v1/ping", server.ping)
	router.GET("/api/v1/healthz", server.healthz)
	router.GET("/api/v1/forwardAuth", server.forwardAuth)
	router.GET("/api/v1/metrics", server.metrics)

	//server.Metrics.requestProcessed = prometheus.NewCounter(prometheus.CounterOpts{
	//	Name: "traefik_coraza_bouncer_processed_request_total",
	//	Help: "The total number of processed requests",
	//})
	server.Metrics.requestProcessed = promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "traefik_coraza_bouncer_processed_request_total",
		Help: "The total number of processed requests",
	})

	server.router = router
	return
}

/*
	Main route used by Traefik to verify authorization for a request
*/
func (server *Server) forwardAuth(c *gin.Context) {
	server.Metrics.requestProcessed.Inc()

	// Parsing int
	serverPort, err := strconv.Atoi(c.Request.Header.Get(clientPortHeader))
	if err != nil {
		log.Warn().Err(err).Msg("Can't convert server port to int. Access will be forbidden")
		c.String(http.StatusForbidden, "Forbidden")
	}

	request := RequestProperties{
		ClientIp:   c.Request.Header.Get(clientIpHeader),
		ClientPort: server.config.ClientPort, // FIXME use a different property
		ServerIp:   c.Request.Header.Get(serverHostHeader),
		ServerPort: serverPort,
		Headers:    c.Request.Header.Clone(),
	}
	request.Headers.Del(clientIpHeader)
	request.Headers.Del(clientPortHeader)
	request.Headers.Del(serverHostHeader)

	interrupt := server.waf.ProcessRequest(request)
	if interrupt != nil {
		c.String(interrupt.Status, "")
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Route to check bouncer WAF capability. Mainly use for Kubernetes readiness probe
*/
func (server *Server) healthz(c *gin.Context) {
	request := RequestProperties{
		ClientIp:   server.config.ClientIp,
		ClientPort: server.config.ClientPort,
		ServerIp:   server.config.ServerIp,
		ServerPort: server.config.ServerPort,
	}
	interrupt := server.waf.ProcessRequest(request)
	if interrupt != nil {
		c.String(interrupt.Status, "")
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Simple route responding pong to every request. Mainly use for Kubernetes liveliness probe
*/
func (server *Server) ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func (server *Server) metrics(c *gin.Context) {
	handler := promhttp.HandlerFor(server.Metrics.registry, promhttp.HandlerOpts{})
	handler.ServeHTTP(c.Writer, c.Request)
}

func (server *Server) Start() error {
	return server.router.Run()
}
