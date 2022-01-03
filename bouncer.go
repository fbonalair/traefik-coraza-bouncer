package bouncer

import (
	"os"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
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
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	router.GET("/api/v1/ping", Ping)
	router.GET("/api/v1/healthz", Healthz)
	router.GET("/api/v1/forwardAuth", ForwardAuth)
	router.GET("/api/v1/metrics", Metrics)
	return router
}
