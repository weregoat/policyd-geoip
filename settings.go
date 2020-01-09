package main

import (
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"github.com/weregoat/goat-whois/pkg/whois"
	"github.com/weregoat/goat-whois/pkg/whois/sources/program"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
)

// The default interval for refreshing the configuration.
const DefaultInterval = time.Minute * 30

// Configuration is the struct holding the description of the YAML fields.
type Configuration struct {
	Path            string
	Debug           bool     `yaml:"debug"`
	Blacklist       []string `yaml:"blacklist"`
	GeoIP2Database  string   `yaml:"geoip2_database"`
	RefreshInterval string   `yaml:"refresh_interval"`
	Whitelist       []string `yaml:"whitelist"`
	Facility        string   `yaml:"syslog_facility"`
	Tag             string   `yaml:"syslog_tag"`
	RejectMessage   string   `yaml:"reject_message"`
	WhoisProgram    string   `yaml:"whois_program"`
	CheckSenderAddress bool  `yaml:"check_sender_address"`
}

// Settings is the struct holding the properties required by the program after
// they have been parsed from the configuration.
type Settings struct {
	Debug              bool
	Syslog             Syslog
	GeoIP2Database     string
	BlackList          []string
	RefreshInterval    time.Duration
	WhiteList          []string
	WhoisClient        *whois.Client
	RejectMessage      string
	CheckSenderAddress bool
	Configuration      Configuration
}

// loadConfiguration opens a configuration file and parses the YAML into a struct.
func loadConfiguration(path string) (Configuration, error) {
	var config Configuration
	filename, err := filepath.Abs(path)
	if err != nil {
		return config, err
	}
	config.Path = filename
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}
	err = yaml.Unmarshal(yamlFile, &config)
	return config, err
}

// parseConfiguration converts the properties of a Configuration struct into
// a Settings struct.
func parseConfiguration(config Configuration) (settings Settings, err error) {
	settings.Configuration = config
	debug := config.Debug
	facility, err := getFacility(config.Facility)
	logger := Syslog{
		Facility:  facility,
		Debugging: debug,
		Tag:       config.Tag,
	}
	if err != nil {
		logger.Warning(
			fmt.Sprintf(
				"Failed to intialize syslog logging: %s",
				err.Error(),
			),
		)
	}
	settings.Syslog = logger

	settings.BlackList = getList(logger, "blacklist", config.Blacklist...)
	settings.WhiteList = getList(logger, "whitelist", config.Whitelist...)

	if len(config.GeoIP2Database) > 0 {
		settings.GeoIP2Database, err = geoip2DatabasePath(config.GeoIP2Database)
		if err != nil {
			logger.Warning(err.Error())
		}
	} else {
		logger.Notice(
			fmt.Sprintf(
				"No GeoIP2 database path defined in configuration file %s",
				config.Path,
			),
		)
	}

	var interval time.Duration
	if len(config.RefreshInterval) > 0 {
		interval, err = time.ParseDuration(config.RefreshInterval)
		if err != nil {
			logger.Warning(
				fmt.Sprintf(
					"Error parsing refresh time element in configuration file %s: %s",
					config.Path,
					err.Error(),
				),
			)
		}
	}
	if interval == 0 { // Duration is an int64
		interval = DefaultInterval
	}
	settings.RefreshInterval = interval

	if len(config.WhoisProgram) > 0 {
		source, err := program.New(config.WhoisProgram)
		if err != nil {
			logger.Warning(
				fmt.Sprintf(
					"Error accessing Whois program at %s: %s",
					config.WhoisProgram,
					err.Error(),
				),
			)
		} else {
			client := whois.New(source)
			settings.WhoisClient = &client
		}
	}
	settings.CheckSenderAddress = config.CheckSenderAddress

	rejectMessage := strings.TrimSpace(config.RejectMessage)
	if len(rejectMessage) > 0 {
		settings.RejectMessage = rejectMessage
	}
	return
}



// getList tries to build unique white and blacklists.
func getList(logger Syslog, name string, list ...string) []string {
	var entries []string
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		// Special treatment for IsoCodes
		switch name {
		case "blacklist":
			if len(entry) == 2 {
				entry = strings.ToUpper(entry)
			} else {
				logger.Notice(fmt.Sprintf("ignoring invalid string '%s' for ISO Country code", entry))
				entry = ""
			}
		}
		duplicate := false
		if len(entry) > 0 {
			for _, present := range entries {
				if entry == present {
					message := fmt.Sprintf("duplicated entry '%s' in %s", entry, name)
					logger.Debug(message)
					duplicate = true
				}
			}
			if !duplicate {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

// geoip2DatabasePath checks the path to the GeoIP2 works.
func geoip2DatabasePath(path string) (checked string, err error) {
	var db *geoip2.Reader
	checked, err = filepath.Abs(path)
	if err != nil {
		return
	} else {
		db, err = geoip2.Open(checked)
		if err != nil {
			return
		}
		defer db.Close()
		return
	}
}

// Show will return strings with the properties.
func (s Settings) Show() []string {
	settings := []string{
		fmt.Sprintf("Configuration file: %s", s.Configuration.Path),
		fmt.Sprintf("GeoIP2 database: %s", s.GeoIP2Database),
		fmt.Sprintf("Refresh interval: %s", s.RefreshInterval),
		fmt.Sprintf("Syslog tag: %s", s.Syslog.Tag),
		fmt.Sprintf("Syslog facility: %s", getPriorityName(s.Syslog.Facility)),
		fmt.Sprintf("Blacklist: %q", s.BlackList),
		fmt.Sprintf("Whitelist: %q", s.WhiteList),
		fmt.Sprintf("Whois program: %s", s.Configuration.WhoisProgram),
		fmt.Sprintf("Check sender address: %t", s.CheckSenderAddress),
		fmt.Sprintf("reject message: %s", s.RejectMessage),
	}
	return settings
}


