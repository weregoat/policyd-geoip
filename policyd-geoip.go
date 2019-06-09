package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"goat-whois/whois/sources"
	"goat-whois/whois/sources/program"
	"goat-whois/whois/sources/server"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Constants and default values
const Dunno = "dunno"
const Blacklisted = "reject Not interested"
const Reject = "reject"
const Defer = "defer_if_permit"
const DefaultGeoIP2Database = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
const DefaultConfigurationFile = "/etc/policyd-geoip.yaml"
const DefaultRefreshInterval = "30m"
const DefaultSyslogFacility = syslog.LOG_MAIL

var debug = false
var blacklistedCountries []string
var whitelistedClients []string
var geoIP2Database = DefaultGeoIP2Database
var refreshInterval, _ = time.ParseDuration(DefaultRefreshInterval)
var SyslogTag string
var SyslogFacility = DefaultSyslogFacility
var whoisSources []sources.Source

type Configuration struct {
	Debug           bool               `yaml:"debug,omitempty"`
	Blacklist       []string           `yaml:"blacklist"`
	GeoIP2Database  string             `yaml:"geoip2_database"`
	RefreshInterval string             `yaml:"refresh_interval"`
	Whitelist       []string           `yaml:"whitelist"`
	Facility        string             `yaml:"syslog_facility"`
	Tag             string             `yaml:"syslog_tag"`
	Whois           WhoisConfiguration `yaml:"whois"`
}

type WhoisConfiguration struct {
	Program string `yaml:"program"`
	Server  string `yaml:"server"`
}

func main() {
	start := time.Now()
	sendToSyslog(syslog.LOG_INFO, "program started")
	configuration := flag.String("configuration", DefaultConfigurationFile, "Path to the configuration")
	flag.Parse()
	SyslogTag = path.Base(os.Args[0]) // Defaults to the name of the executable
	loadConfiguration(*configuration)

	response := Defer

	scanner := bufio.NewScanner(os.Stdin)
	ip := ""
	clientName := ""
	for scanner.Scan() {
		begin := time.Now()
		line := scanner.Text()
		sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("read line '%s' from stdin", line))
		if strings.Contains(line, "=") {
			values := strings.Split(scanner.Text(), "=")
			key := values[0]
			value := values[1]
			switch key {
			case "client_address":
				elapsed := time.Since(start)
				if elapsed.Minutes() >= refreshInterval.Minutes() {
					sendToSyslog(syslog.LOG_DEBUG, "refreshing configuration")
					loadConfiguration(*configuration)
					start = time.Now()
				}
				ip = value
			case "client_name":
				clientName = value
			}
		}
		if scanner.Text() == "" {
			if checkWhitelist(clientName) == false {
				response = checkBlacklist(ip, clientName)
			} else {
				response = Dunno
			}
			actionLine := fmt.Sprintf("action=%s", response)
			sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("sending response '%s' to stdout", actionLine))
			writer := bufio.NewWriter(os.Stdout)
			writer.WriteString(fmt.Sprintf("%s\n\n", actionLine))
			processDuration := time.Since(begin)
			sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("processed in %s", processDuration.String()))
			writer.Flush()
			clientName = ""
			ip = ""
			response = Defer
		}
	}
	if err := scanner.Err(); err != nil {
		sendToSyslog(syslog.LOG_ERR, err.Error())
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

}

func sendToSyslog(level syslog.Priority, message string) {

	sysLog, err := syslog.Dial("", "", level|SyslogFacility, SyslogTag)
	if err != nil {
		log.Fatal(err)
	}
	if debug == false {
		if level != syslog.LOG_DEBUG {
			fmt.Fprint(sysLog, message)
		}
	} else {
		fmt.Fprint(sysLog, message)
	}
}

func checkBlacklist(ipAddress string, clientName string) string {
	response := Defer
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		checkGeoIP2(&response, geoIP2Database, ip) // Check the IP address using Geoip2
		if len(whoisSources) > 0 { // If any of the Whois sources have been configured correctly
			checkWhois(&response, ip.String())             // Check the Provider country using the IP
			checkWhois(&response, getDomain(clientName)) // Check the Registrant through the client's domain
		}
	} else {
		sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("invalid client address '%s'", ipAddress))
		response = Reject
	}
	return response
}

func checkGeoIP2(response *string, database string, ip net.IP) {
	if ip != nil && (*response == Dunno || *response == Defer) {
		isoCode := geoIP2Lookup(ip, database)
		if isoCode != "" {
			*response = Dunno
			result := "allowed"
			level := syslog.LOG_DEBUG
			if isCountryCodeBlacklisted(blacklistedCountries, isoCode) {
				*response = Blacklisted
				result = "not allowed"
				level = syslog.LOG_INFO
			}
			sendToSyslog(level, fmt.Sprintf("client with address %s from country %s is %s", ip.String(), isoCode, result))
		} else {
			sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("no country found for address %s", ip.String()))
			*response = Reject
		}
	}
}

func loadConfiguration(configuration string) {

	filename, err := filepath.Abs(configuration)
	if err != nil {
		sendToSyslog(syslog.LOG_ERR, err.Error())
	}

	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		sendToSyslog(syslog.LOG_ERR, err.Error())
	} else {
		var config Configuration
		err = yaml.Unmarshal(yamlFile, &config)
		if err != nil {
			sendToSyslog(syslog.LOG_ERR, err.Error())
		} else {
			parseConfiguration(config)
		}
	}
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("configuration file: %s", filename))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("debug: %t", debug))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("blacklisted countries: %v", blacklistedCountries))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("geoip2 database: %v", geoIP2Database))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("refresh time: %s", refreshInterval.String()))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("whitelisted clients: %v", whitelistedClients))
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("whois sources: %v", whoisSources))
}

func checkWhitelist(clientName string) bool {
	allow := false
	for _, allowedClient := range whitelistedClients {
		match := strings.HasSuffix(strings.ToLower(strings.TrimSpace(clientName)), allowedClient)
		if match == true {
			sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("client %s is whitelisted under %s", clientName, allowedClient))
			allow = true
			break
		}
	}
	return allow
}

func parseConfiguration(config Configuration) {

	if len(config.Tag) > 0 {
		SyslogTag = strings.TrimSpace(config.Tag)
	}

	if len(config.Facility) > 0 {
		switch strings.ToLower(strings.TrimSpace(config.Facility)) {
		// Not all the possible facility name are here; just the ones I think make sense.
		case "mail":
			SyslogFacility = syslog.LOG_MAIL
		case "user":
			SyslogFacility = syslog.LOG_USER
		case "daemon":
			SyslogFacility = syslog.LOG_DAEMON
		case "auth":
			SyslogFacility = syslog.LOG_AUTH
		case "authpriv":
			SyslogFacility = syslog.LOG_AUTHPRIV
		case "local0":
			SyslogFacility = syslog.LOG_LOCAL0
		case "local1":
			SyslogFacility = syslog.LOG_LOCAL1
		case "local2":
			SyslogFacility = syslog.LOG_LOCAL2
		case "local3":
			SyslogFacility = syslog.LOG_LOCAL3
		case "local4":
			SyslogFacility = syslog.LOG_LOCAL4
		case "local5":
			SyslogFacility = syslog.LOG_LOCAL5
		case "local6":
			SyslogFacility = syslog.LOG_LOCAL6
		case "local7":
			SyslogFacility = syslog.LOG_LOCAL7
		default:
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("ignoring improper or unknown name '%s' for syslog facility", config.Facility))
			config.Facility = "mail"
		}
	}

	// Empty the existing blacklist
	blacklistedCountries = blacklistedCountries[:0]
	for _, blacklistedCountry := range config.Blacklist {
		isoCode := strings.TrimSpace(blacklistedCountry)
		if len(isoCode) == 2 {
			blacklistedCountries = append(blacklistedCountries, strings.ToUpper(isoCode))
		} else {
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("ignoring invalid string '%s' for ISO Country code", blacklistedCountry))
		}
	}

	whitelistedClients = whitelistedClients[:0]
	for _, whitelistedClient := range config.Whitelist {
		clientName := strings.ToLower(strings.TrimSpace(whitelistedClient))
		if len(clientName) > 0 && strings.Contains(clientName, ".") {
			whitelistedClients = append(whitelistedClients, clientName)
		} else {
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("ignoring invalid string '%s' for client name", clientName))
		}
	}

	debug = config.Debug

	databaseFile, err := filepath.Abs(config.GeoIP2Database)
	if err != nil {
		sendToSyslog(syslog.LOG_WARNING, err.Error())
	} else {
		_, err := os.Stat(databaseFile)
		if err == nil {
			geoIP2Database = databaseFile
		} else {
			sendToSyslog(syslog.LOG_WARNING, err.Error())
		}
	}

	interval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil {
		sendToSyslog(syslog.LOG_WARNING, err.Error())
	} else {
		refreshInterval = interval
	}

	whoisSources = whoisSources[:0]
	whoisProgram := config.Whois.Program
	if len(whoisProgram) > 0 {
		source, err := program.New(whoisProgram)
		if err == nil {
			whoisSources = append(whoisSources, source)
		} else {
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("could not use whois program %s because of error %s", whoisProgram, err.Error()))
		}
	}

	whoisServer := config.Whois.Server
	if len(whoisServer) > 0 {
		source, err := server.New(whoisServer)
		if err == nil {
			whoisSources = append(whoisSources, source)
		} else {
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("could not use whois server %s because of error: %s", whoisServer, err.Error()))
		}
	}
}

func checkWhois(response *string, resource string) {
	if len(resource) > 0 && (*response == Dunno || *response == Defer) {
		for _, source := range whoisSources {
			sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("querying whois source %s for information about resource %s", source, resource))
			whoisResponse := source.Query(resource)
			if whoisResponse.IsValid() {
				isoCode := whoisResponse.CountryCode
				if len(isoCode) > 0 {
					sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("found country code %s for resource %s", isoCode, resource))
					if isCountryCodeBlacklisted(blacklistedCountries, isoCode) {
						*response = Blacklisted
						sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("resource %s from country code %s is not allowed", resource, isoCode))
						break
					}
				} else {
					sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("no country code was found for resource %s", resource))
				}
				break // One valid answer is enough. The second source is a fallback.
			} else {
				sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("no valid whois response from %s on resource %s", source, resource))
			}
		}
	}
}

func getDomain(fqdn string) string {
	var domain string
	// https://en.wikipedia.org/wiki/Fully_qualified_domain_name
	parts := strings.SplitN(fqdn, ".", 2)
	// The FQDN should have been split into a hostname parts[0]
	// and a domain parts[1]
	if len(parts) == 2 {
		// It's still possible, by the split above, that the domain
		// is not really a domain, because the hostname was missing
		// Then it was not really a fqdn, but a domain
		if strings.Index(parts[1], ".") > 0 {
			domain = parts[1]
		} else {
			domain = fqdn
		}
	}
	return domain
}

func isCountryCodeBlacklisted(blacklist []string, isoCodes ...string) bool {
	sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("checking ISO country codes %q against blacklist %q", isoCodes, blacklist))
	for _, isoCode := range isoCodes {
		if len(isoCode) > 0 {
			for _, blacklistedIsoCode := range blacklist {
				if isoCode == blacklistedIsoCode {
					sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("ISO country code %s is blacklisted", isoCode))
					return true
				}
			}
			sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("ISO country code %s is not blacklisted", isoCode))
		} else {
			sendToSyslog(syslog.LOG_DEBUG, "no ISO country code passed to function")
		}
	}
	return false
}

// geoIP2Lookup
func geoIP2Lookup(ip net.IP, database string) string {
	var isoCode string
	if ip != nil {
		sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("looking up country of address %s from GeoIP2 database %s", ip.String(), database))
		db, err := geoip2.Open(database)
		if err != nil {
			sendToSyslog(syslog.LOG_ERR, err.Error())
		} else {
			defer db.Close()
			record, err := db.Country(ip)
			if err != nil {
				sendToSyslog(syslog.LOG_ERR, err.Error())
			} else {
				isoCode = record.Country.IsoCode
				if len(isoCode) > 0 {
					sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("geoIP2 database lists address %s as from country %s", ip.String(), isoCode))
				} else {
					sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("no country found for address %s", ip.String()))
				}
			}
		}
	}
	return isoCode
}