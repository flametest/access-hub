package config

import (
	"errors"
	"fmt"
	"time"

	log "github.com/flametest/vita/vlog"
	"github.com/flametest/vita/vgorm"
	"github.com/flametest/vita/vredis"
	"github.com/flametest/vita/vserver"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

const (
	MailerDriverConsole = "console"
	MailerDriverSMTP    = "smtp"
)

type Config struct {
	AppConfig  vserver.EchoServerConfig `yaml:"AppConfig"`
	LogLevel   log.Level                `yaml:"LogLevel"`
	Datasource *vgorm.Config            `yaml:"Datasource"`
	Redis      *vredis.Config           `yaml:"Redis"`
	Auth       AuthConfig               `yaml:"Auth"`
	Mailer     MailerConfig             `yaml:"Mailer"`
	Bootstrap  BootstrapConfig          `yaml:"Bootstrap"`
}

type AuthConfig struct {
	AccessTokenTTL       time.Duration `yaml:"accessTokenTTL"`
	RefreshTokenTTL      time.Duration `yaml:"refreshTokenTTL"`
	RSAPrivateKeyPath    string        `yaml:"rsaPrivateKeyPath"`
	RSAPublicKeyPath     string        `yaml:"rsaPublicKeyPath"`
	EmailCodeTTL         time.Duration `yaml:"emailCodeTTL"`
	EmailCodeMaxAttempts int           `yaml:"emailCodeMaxAttempts"`
	SendCodeInterval     time.Duration `yaml:"sendCodeInterval"`
	SendCodeIPLimit      int           `yaml:"sendCodeIPLimit"`
	LoginMaxAttempts     int           `yaml:"loginMaxAttempts"`
	LoginLockDuration    time.Duration `yaml:"loginLockDuration"`
	AllowAutoRegister    bool          `yaml:"allowAutoRegister"`
	BcryptCost           int           `yaml:"bcryptCost"`
}

type MailerConfig struct {
	Driver string     `yaml:"driver"`
	SMTP   SMTPConfig `yaml:"smtp"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

type BootstrapConfig struct {
	AdminUsername string `yaml:"adminUsername"`
	AdminEmail    string `yaml:"adminEmail"`
	AdminPassword string `yaml:"adminPassword"`
}

func ParseConfig(path string) (*Config, error) {
	cfg := &Config{}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := v.Unmarshal(cfg, func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(mapstructure.StringToTimeDurationHookFunc())
	}); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.AppConfig.Name == "" {
		return errors.New("app_config.name is required")
	}
	if c.AppConfig.Addr == "" {
		return errors.New("app_config.addr is required")
	}
	if c.Datasource == nil {
		return errors.New("datasource is required")
	}
	if c.Redis == nil {
		return errors.New("redis is required")
	}
	switch c.Mailer.Driver {
	case MailerDriverConsole:
	case MailerDriverSMTP:
		if c.Mailer.SMTP.Host == "" || c.Mailer.SMTP.From == "" {
			return errors.New("mailer.smtp.host and mailer.smtp.from are required for the smtp driver")
		}
	default:
		return fmt.Errorf("mailer.driver must be %q or %q", MailerDriverConsole, MailerDriverSMTP)
	}
	if c.Auth.AccessTokenTTL <= 0 {
		return errors.New("auth.accessTokenTTL must be positive (e.g. 15m)")
	}
	if c.Auth.RefreshTokenTTL <= c.Auth.AccessTokenTTL {
		return errors.New("auth.refreshTokenTTL must exceed accessTokenTTL")
	}
	if c.Auth.RSAPrivateKeyPath == "" || c.Auth.RSAPublicKeyPath == "" {
		return errors.New("auth.rsaPrivateKeyPath / auth.rsaPublicKeyPath are required (run `make keys`)")
	}
	if c.Auth.EmailCodeTTL <= 0 || c.Auth.SendCodeInterval <= 0 {
		return errors.New("auth.emailCodeTTL and auth.sendCodeInterval must be positive")
	}
	if c.Auth.EmailCodeMaxAttempts <= 0 || c.Auth.SendCodeIPLimit <= 0 || c.Auth.LoginMaxAttempts <= 0 {
		return errors.New("auth attempt limits must be positive")
	}
	if c.Auth.LoginLockDuration <= 0 {
		return errors.New("auth.loginLockDuration must be positive")
	}
	if c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return errors.New("auth.bcryptCost must be within [4,31]")
	}
	if c.Bootstrap.AdminUsername == "" || c.Bootstrap.AdminEmail == "" {
		return errors.New("bootstrap.adminUsername / bootstrap.adminEmail are required")
	}
	return nil
}
