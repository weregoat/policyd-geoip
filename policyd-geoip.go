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
const DefaultConfigurationFile = "/usr/local/etc/policyd-geoip.yaml"
const DefaultRefreshInterval = "30m"

var debug = false
var blacklistedCountries []string
var geoIP2Database = DefaultGeoIP2Database
var refreshInterval,_ = time.ParseDuration(DefaultRefreshInterval)


type Configuration struct {
	Debug bool `yaml:"debug,omitempty"`
	BlackList []string `yaml:"blacklist"`
	GeoIP2Database string `yaml:"geoip2_database"`
	RefreshInterval string `yaml:"refresh_interval"`
}


func main() {
	start := time.Now()
	sysLog(syslog.LOG_INFO, "program started")
	configuration := flag.String("configuration", DefaultConfigurationFile, "Path to the configuration")
	flag.Parse()
	loadConfiguration(*configuration)

	response := Dunno
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		begin := time.Now()
		line := scanner.Text()
		sysLog(syslog.LOG_DEBUG, fmt.Sprintf("read line '%s' from stdin", line))
		if strings.Contains(line, "=") {
			values := strings.Split(scanner.Text(), "=")
			if values[0] == "client_address" {
				elapsed := time.Since(start)
				if elapsed.Minutes() >= refreshInterval.Minutes() {
					sysLog(syslog.LOG_INFO, "refreshing configuration")
					loadConfiguration(*configuration)
					start = time.Now()
				}
				ip := values[1]
				response = checkBlacklist(geoIP2Database, ip)
			}
		}
		if scanner.Text() == "" {
			actionLine := fmt.Sprintf("action=%s",response)
			sysLog(syslog.LOG_DEBUG, fmt.Sprintf("sending response '%s' to stdout", actionLine))
			writer := bufio.NewWriter(os.Stdout)
			writer.WriteString(fmt.Sprintf("%s\n\n",actionLine))
			processDuration := time.Since(begin)
			sysLog(syslog.LOG_INFO, fmt.Sprintf("processed in %s", processDuration.String()))
			writer.Flush()
		}
	}
	if err := scanner.Err(); err != nil {
		sysLog(syslog.LOG_ERR, err.Error())
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}



}

func sysLog(level syslog.Priority, message string) {

	sysLog, err := syslog.Dial("", "", level|syslog.LOG_MAIL, "policyd-geoip")
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
		sysLog(syslog.LOG_ERR, err.Error())
	} else {
		defer db.Close()
		ip := net.ParseIP(ipAddress)
		if ip != nil {
			record, err := db.Country(ip)
			if err != nil {
				sysLog(syslog.LOG_ERR, err.Error())
			} else {
				isoCode := record.Country.IsoCode
				if isoCode != "" {
					sysLog(syslog.LOG_DEBUG, fmt.Sprintf("geoIP2 database lists address %s as from country %s", ipAddress, isoCode))
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
					sysLog(syslog.LOG_INFO, fmt.Sprintf("client with address %s from country %s is %s", ipAddress, isoCode, result))

				} else {
					sysLog(syslog.LOG_NOTICE, fmt.Sprintf("no country found for address %s", ipAddress))
					response = Reject
				}
			}
		} else {
			sysLog(syslog.LOG_NOTICE, fmt.Sprintf("invalid client address '%s'", ipAddress))
			response = Reject
		}
	}
	return response
}

func loadConfiguration(configuration string) {
	var blacklist []string
	filename, err := filepath.Abs(configuration)
	if err != nil {
		sysLog(syslog.LOG_ERR,err.Error())
	}
	sysLog(syslog.LOG_INFO, fmt.Sprintf("importing configuration file %s", filename))
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		sysLog(syslog.LOG_ERR,err.Error())
	} else {
		var config Configuration
		err = yaml.Unmarshal(yamlFile, &config)
		if err == nil {
			for _, blacklistedCountry := range config.BlackList {
				isoCode := strings.TrimSpace(blacklistedCountry)
				if len(isoCode) == 2 {
					blacklist = append(blacklist, blacklistedCountry)
				} else {
					sysLog(syslog.LOG_WARNING, fmt.Sprintf("ignoring invalid string '%s' for ISO Country code", blacklistedCountry))
				}
			}
		}
		if len(blacklist) == 0 {
			sysLog(syslog.LOG_WARNING, fmt.Sprintf("no valid blacklist found in configuration file %s", filename))
		} else {
			blacklistedCountries = blacklist
		}
		debug = config.Debug
		databaseFile, err := filepath.Abs(config.GeoIP2Database)
		if err != nil {
			sysLog(syslog.LOG_WARNING, err.Error())
		} else {
			_, err := os.Stat(databaseFile)
			if err == nil {
				geoIP2Database = databaseFile
			} else {
				sysLog(syslog.LOG_WARNING, err.Error())
			}
		}
		interval, err := time.ParseDuration(config.RefreshInterval)
		if err != nil {
			sysLog(syslog.LOG_WARNING, err.Error())
		} else {
			refreshInterval = interval
		}

	}
	sysLog(syslog.LOG_INFO, fmt.Sprintf("debug: %v", debug))
	sysLog(syslog.LOG_INFO, fmt.Sprintf("blacklisted countries: %v", blacklistedCountries))
	sysLog(syslog.LOG_INFO, fmt.Sprintf("geoip2 database: %v", geoIP2Database))
	sysLog(syslog.LOG_INFO, fmt.Sprintf("refresh time: %s", refreshInterval.String()))
}

