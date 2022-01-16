package main

import (
	"github.com/rs/zerolog/log"
	. "github.com/spf13/viper"
	"os"
)

type SecRules struct {
	CustomRule          string `mapstructure:"custom_rule"`
	CustomPath          string `mapstructure:"custom_path"`
	DownloadedPath      string `mapstructure:"downloaded_path"`
	Recommended         bool
	RecommendedUrl      string `mapstructure:"recommended_url"`
	Owasp               bool
	OwaspUrl            string `mapstructure:"owasp_url"`
	OwaspSha            string `mapstructure:"owasp_sha"`
	OwaspUrlExampleFile string `mapstructure:"owasp_example_file"`
}
type HealthzRoute struct {
	ClientIp   string `mapstructure:"client_ip"`
	ClientPort int    `mapstructure:"client_port"`
	ServerIp   string `mapstructure:"server_ip"`
	ServerPort int    `mapstructure:"server_port"`
}
type Config struct {
	SecRules     `mapstructure:"sec_rules"`
	HealthzRoute `mapstructure:"healthz_route"`

	ClientPort int `mapstructure:"client_port"`
}

func ParseConfig(configPath string, viper *Viper) (config Config) {

	viper.SetEnvPrefix("BOUNCER")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)

	viper.SetDefault("SEC_RULES.CUSTOM_PATH", "/etc/bouncer/rules/custom/*")
	viper.SetDefault("SEC_RULES.DOWNLOADED_PATH", "/etc/bouncer/rules/downloaded/")
	viper.SetDefault("SEC_RULES.RECOMMENDED", true)
	viper.SetDefault("SEC_RULES.RECOMMENDED_URL", "https://raw.githubusercontent.com/jptosso/coraza-waf/v2/master/coraza.conf-recommended")
	viper.SetDefault("SEC_RULES.OWASP", true)
	viper.SetDefault("SEC_RULES.OWASP_URL", "https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.tar.gz")
	viper.SetDefault("SEC_RULES.OWASP_EXAMPLE_FILE", "crs-setup.conf.example")

	viper.SetDefault("HEALTHZ_ROUTE.CLIENT_IP", "192.168.1.1")
	viper.SetDefault("HEALTHZ_ROUTE.CLIENT_PORT", 12345)
	viper.SetDefault("HEALTHZ_ROUTE.SERVER_IP", "10.42.1.1")
	viper.SetDefault("HEALTHZ_ROUTE.SERVER_PORT", 8080)

	viper.SetDefault("CLIENT_PORT", 5489)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(ConfigFileNotFoundError); ok {
			// Writing Config file if not found
			err = os.MkdirAll(configPath, 0755)
			if err != nil {
				log.Fatal().Err(err).Msgf("error while accessing dir %s", configPath)
			}
			err := viper.SafeWriteConfig()
			if err != nil {
				log.Fatal().Err(err).Msg("Could not save Config file")
			}
		} else {
			log.Fatal().Err(err).Msg("Fatal error while reading Config file")
		}
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Fatal().Err(err).Msg("Unable to decode Config into struct")
	}
	return
}
