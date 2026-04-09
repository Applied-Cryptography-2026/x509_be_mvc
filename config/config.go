package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

// config holds all application configuration values.
type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Server   ServerConfig   `mapstructure:"server"`
	PKI      PKIConfig      `mapstructure:"pki"`
	App      AppConfig      `mapstructure:"app"`
	JWT      JWTConfig      `mapstructure:"jwt"`
}

// JWTConfig holds JWT token settings.
type JWTConfig struct {
	AccessTokenSecret  string `mapstructure:"access_token_secret"`
	RefreshTokenSecret string `mapstructure:"refresh_token_secret"`
	AccessTokenTTL     int    `mapstructure:"access_token_ttl_minutes"`
	RefreshTokenTTL    int    `mapstructure:"refresh_token_ttl_days"`
	Issuer             string `mapstructure:"issuer"`
}

// DatabaseConfig holds MySQL connection parameters.
type DatabaseConfig struct {
	User                 string            `mapstructure:"user"`
	Password             string            `mapstructure:"password"`
	Net                  string            `mapstructure:"net"`
	Addr                 string            `mapstructure:"addr"`
	DBName               string            `mapstructure:"dbname"`
	AllowNativePasswords bool              `mapstructure:"allowNativePasswords"`
	Params               map[string]string `mapstructure:"params"`
}

// ServerConfig holds HTTP server parameters.
type ServerConfig struct {
	Address string `mapstructure:"address"`
	Mode    string `mapstructure:"mode"` // debug, release, test
}

// PKIConfig holds x509/PKI-specific settings.
type PKIConfig struct {
	DefaultValidityDays int      `mapstructure:"default_validity_days"`
	DefaultKeyBits      int      `mapstructure:"default_key_bits"`
	DefaultProfile      string   `mapstructure:"default_profile"`
	AllowedProfiles     []string `mapstructure:"allowed_profiles"`
	DefaultKeyUsage     []string `mapstructure:"default_key_usage"`
	DefaultExtKeyUsage  []string `mapstructure:"default_ext_key_usage"`
	CACommonName        string   `mapstructure:"ca_common_name"`
	CAOrganization      string   `mapstructure:"ca_organization"`
	CRLURL              string   `mapstructure:"crl_url"`
	OCSPURL             string   `mapstructure:"ocsp_url"`
}

// AppConfig holds general application settings.
type AppConfig struct {
	Env            string `mapstructure:"env"`
	NotifyDays     int    `mapstructure:"notify_days"`      // days before expiry to send alerts
	StorageDir     string `mapstructure:"storage_dir"`      // path to store cert/key PEM files
	PrivateKeyPass string `mapstructure:"private_key_pass"` // passphrase for encrypting stored keys
}

// C is the global singleton config instance.
var C Config

// ReadConfig loads configuration from a YAML file using Viper.
func ReadConfig() {
	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(filepath.Join(rootDir(), "config"))
	v.AddConfigPath(".")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		fmt.Printf("config: failed to read config file: %v\n", err)
		log.Fatalln(err)
	}

	if err := v.Unmarshal(&C); err != nil {
		fmt.Printf("config: failed to unmarshal config: %v\n", err)
		os.Exit(1)
	}
}

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(b))
}
