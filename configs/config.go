package configs

import (
	"github.com/rs/zerolog/log"
	. "github.com/spf13/viper"
	"os"
)

type Config struct {
	SecRules struct {
		CustomRule          string `mapstructure:"custom_rule"`
		CustomPath          string `mapstructure:"custom_path"`
		DownloadedPath      string `mapstructure:"downloaded_path"`
		Recommended         bool
		RecommendedUrl      string `mapstructure:"recommended_url"`
		Owasp               bool
		OwaspUrl            string `mapstructure:"owasp_url"`
		OwaspUrlExampleFile string `mapstructure:"owasp_example_file"`
	} `mapstructure:"sec_rules"`
}

var Values Config

func init() {
	configPath := os.Getenv("BOUNCER_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/bouncer/"
	}

	SetEnvPrefix("BOUNCER")
	SetConfigName("config")
	SetConfigType("yaml")
	AddConfigPath(configPath)
	SetDefault("SEC_RULES.CUSTOM_PATH", "/etc/bouncer/rules/custom/*")
	SetDefault("SEC_RULES.DOWNLOADED_PATH", "/etc/bouncer/rules/downloaded")
	SetDefault("SEC_RULES.RECOMMENDED", "true")
	SetDefault("SEC_RULES.RECOMMENDED_URL", "https://raw.githubusercontent.com/jptosso/coraza-waf/v2/master/coraza.conf-recommended")
	SetDefault("SEC_RULES.OWASP", "true")
	SetDefault("SEC_RULES.OWASP_URL", "https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.tar.gz")
	SetDefault("SEC_RULES.OWASP_EXAMPLE_FILE", "crs-setup.conf.example")
	AutomaticEnv()

	if err := ReadInConfig(); err != nil {
		if _, ok := err.(ConfigFileNotFoundError); ok {
			// Writing Config file if not found
			err := SafeWriteConfig()
			if err != nil {
				log.Fatal().Err(err).Msg("Could not save Config file")
			}
		} else {
			log.Fatal().Err(err).Msg("Fatal error while reading Config file")
		}
	}

	if err := Unmarshal(&Values); err != nil {
		log.Fatal().Err(err).Msg("unable to decode Config into struct")
	}
}
