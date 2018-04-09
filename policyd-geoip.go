package main

import (
	"github.com/oschwald/geoip2-golang"
	"log"
	"log/syslog"
	"net"
	"fmt"
	"bufio"
	"os"
	"strings"
	"flag"
	"gopkg.in/yaml.v2"
	"path/filepath"
	"io/ioutil"
	"time"
)

const Dunno = "dunno"
const Blacklisted = "reject Not interested"
const Reject = "reject"
const Defer = "defer_if_permit"
const DefaultGeoIP2Database = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
const DefaultConfigurationFile = "/etc/policyd-geoip.yaml"
const DefaultRefreshInterval = "30m"
const SyslogFacility = syslog.LOG_MAIL
const SyslogTag = "policyd-geoip"

var debug = false
var blacklistedCountries []string
var whitelistedClients []string
var geoIP2Database = DefaultGeoIP2Database
var refreshInterval,_ = time.ParseDuration(DefaultRefreshInterval)


type Configuration struct {
	Debug bool `yaml:"debug,omitempty"`
	Blacklist []string `yaml:"blacklist"`
	GeoIP2Database string `yaml:"geoip2_database"`
	RefreshInterval string `yaml:"refresh_interval"`
	Whitelist []string `yaml:"whitelist"`
	Facility string `yaml:"syslog_facility"`
	Tag string `yaml:"syslog_tag"`
}


func main() {
	start := time.Now()
	sendToSyslog(syslog.LOG_INFO, "program started")
	configuration := flag.String("configuration", DefaultConfigurationFile, "Path to the configuration")
	flag.Parse()
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
					sendToSyslog(syslog.LOG_INFO, "refreshing configuration")
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
				if len(ip) > 0 {
					response = checkBlacklist(geoIP2Database, ip)
				}
			}
			actionLine := fmt.Sprintf("action=%s",response)
			sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("sending response '%s' to stdout", actionLine))
			writer := bufio.NewWriter(os.Stdout)
			writer.WriteString(fmt.Sprintf("%s\n\n",actionLine))
			processDuration := time.Since(begin)
			sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("processed in %s", processDuration.String()))
			writer.Flush()
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

func checkBlacklist(database string, ipAddress string) string {

	response := Defer
	db, err := geoip2.Open(database)
	if err != nil {
		sendToSyslog(syslog.LOG_ERR, err.Error())
	} else {
		defer db.Close()
		ip := net.ParseIP(ipAddress)
		if ip != nil {
			record, err := db.Country(ip)
			if err != nil {
				sendToSyslog(syslog.LOG_ERR, err.Error())
			} else {
				isoCode := record.Country.IsoCode
				if isoCode != "" {
					sendToSyslog(syslog.LOG_DEBUG, fmt.Sprintf("geoIP2 database lists address %s as from country %s", ipAddress, isoCode))
					response = Dunno
					for _, blacklistedIsoCode := range blacklistedCountries {
						if isoCode == blacklistedIsoCode {
							response = Blacklisted
							break
						}
					}
					result := "allowed"
					if response == Blacklisted {
						result = "not allowed"
					}
					sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("client with address %s from country %s is %s", ipAddress, isoCode, result))

				} else {
					sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("no country found for address %s", ipAddress))
					response = Reject
				}
			}
		} else {
			sendToSyslog(syslog.LOG_NOTICE, fmt.Sprintf("invalid client address '%s'", ipAddress))
			response = Reject
		}
	}
	return response
}

func loadConfiguration(configuration string) {

	filename, err := filepath.Abs(configuration)
	if err != nil {
		sendToSyslog(syslog.LOG_ERR,err.Error())
	}
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("importing configuration file %s", filename))
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		sendToSyslog(syslog.LOG_ERR,err.Error())
	} else {
		var config Configuration
		err = yaml.Unmarshal(yamlFile, &config)
		if err != nil {
			sendToSyslog(syslog.LOG_ERR, err.Error())
		} else {
			parseConfiguration(config)
		}
	}
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("debug: %v", debug))
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("blacklisted countries: %v", blacklistedCountries))
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("geoip2 database: %v", geoIP2Database))
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("refresh time: %s", refreshInterval.String()))
	sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("whitelisted clients: %v", whitelistedClients))
}

func checkWhitelist(clientName string) bool {
	allow := false
	for _,allowedClient := range whitelistedClients {
		match := strings.HasSuffix(strings.ToLower(strings.TrimSpace(clientName)), allowedClient)
		if match == true {
			sendToSyslog(syslog.LOG_INFO, fmt.Sprintf("client %s is whitelisted under %s", clientName,allowedClient))
			allow = true
			break
		}
	}
	return allow
}

func parseConfiguration(config Configuration) {

	for _, blacklistedCountry := range config.Blacklist {
		isoCode := strings.TrimSpace(blacklistedCountry)
		if len(isoCode) == 2 {
			blacklistedCountries = append(blacklistedCountries, isoCode)
		} else {
			sendToSyslog(syslog.LOG_WARNING, fmt.Sprintf("ignoring invalid string '%s' for ISO Country code", blacklistedCountry))
		}
	}

	for _, whitelistedClient := range config.Whitelist {
		clientName := strings.ToLower(strings.TrimSpace(whitelistedClient))
		if len(clientName) > 0 && strings.Contains(clientName, "."){
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

}


