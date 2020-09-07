package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"log/syslog"
	"net"
	"os"
	"strings"
	"time"
)

// Constants and default values
const Dunno = "dunno"
const Reject = "reject"
const Defer = "defer_if_permit"
const DefaultConfigurationFile = "/etc/policyd-geoip.yaml"

// main function
func main() {

	configuration := flag.String("configuration", DefaultConfigurationFile, "Path to the configuration")
	flag.Parse()

	settings, err := readConfig(*configuration)

	// In case of error Postfix documentation suggests to log and exit.
	if err != nil {
		Log(
			syslog.LOG_MAIL,
			syslog.LOG_CRIT,
			"",
			fmt.Sprintf(
				"Failed to read configuration %s: %s",
				*configuration,
				err.Error(),
			),
		)
		fmt.Fprintln(os.Stderr, "Failed to read configuration:", err)
		os.Exit(1)
	}

	settings.Syslog.Info("Program started")
	for _, setting := range settings.Show() {
		settings.Syslog.Debug(setting)
	}
	defer settings.Syslog.Info("Program ended")

	client := Client{}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		response := Dunno
		begin := time.Now()
		line := scanner.Text()
		settings.Syslog.Debug(fmt.Sprintf("Read line '%s' from stdin", line))
		if strings.Contains(line, "=") {
			client.parseLine(line)
		}
		// End of input
		if line == "" {
			if isWhitelisted(client.Name, settings.WhiteList) {
				// Dunno and not OK because, I think, it should only be
				// a way to bypass **this** check. I may change my mind
				// later though.
				response = Dunno
			} else {
				response = checkClient(settings, client)
			}
			switch response {
			case Reject:
				settings.Syslog.Info(
					fmt.Sprintf(
						"Client %s is blacklisted",
						client.String(),
					),
				)
			case Defer:
				settings.Syslog.Notice(
					fmt.Sprintf("Could not fully evaluate client %s",
						client.String(),
					),
				)
			case Dunno:
				settings.Syslog.Debug(
					fmt.Sprintf("Client %s is allowed",
						client.String(),
					),
				)
			default:
				settings.Syslog.Warning(
					fmt.Sprintf("Unhandled response: %s", response),
				)
				response = Defer
			}
			if len(settings.RejectMessage) > 0 && response == Reject {
				// It doesn't really need to be efficient. Clearer this way.
				response = response + " " + settings.RejectMessage
			}
			action := fmt.Sprintf("action=%s", response)
			settings.Syslog.Debug(fmt.Sprintf("Sending response '%s' to stdout", action))
			processDuration := time.Since(begin)
			settings.Syslog.Debug(fmt.Sprintf("Processed in %s", processDuration.String()))
			print(action)
			client.IP = nil
			client.Name = ""
			client.SenderDomain = ""
		}
	}
	if err := scanner.Err(); err != nil {
		settings.Syslog.Err(err.Error())
		fmt.Fprintln(os.Stderr, "Reading standard input:", err)
		os.Exit(1)
	}

}

// readConfig loads and parse the configuration file
func readConfig(path string) (Settings, error) {
	var settings Settings
	config, err := loadConfiguration(path)
	if err != nil {
		return settings, err
	}
	settings, err = parseConfiguration(config)

	return settings, err
}

// print outputs the result as action. Notice action should be followed by an empty
// line.
func print(action string) {
	writer := bufio.NewWriter(os.Stdout)
	writer.WriteString(fmt.Sprintf("%s\n\n", action))
	writer.Flush()
}

// checkClient wraps the various checks for the client.
func checkClient(settings Settings, client Client) string {
	ch := make(chan string)
	count := 0
	if client.IP != nil {
		go checkGeoIP2(settings, client.IP, ch) // Check the IP address using GeoIP2
		count++
		go checkWhois(settings, client.IP.String(), ch)
	}
	if len(client.Name) > 0 {
		go checkTopLevelDomain(settings, client.Name, ch)
		count++
		go checkWhois(settings, client.Name, ch)
		count++
	}
	if len(client.SenderDomain) > 0 {
		go checkTopLevelDomain(settings, client.Name, ch)
		count++
		go checkWhois(settings, client.Name, ch)
		count++
	}
	timeout := time.After(30 * time.Second)
	for i := 0; i < count; i++ {
		select {
		case response := <-ch:
			if response != Dunno {
				return response
			}
		case <-timeout:
			return Dunno
		}
	}
	return Dunno
}

// checkGeoIP2 check the the client's IP address against the GeoIP2 database.
func checkGeoIP2(settings Settings, ip net.IP, ch chan string) {
	if ip != nil {
		isoCode := geoIP2Lookup(settings, ip)
		if len(isoCode) == 2 {
			ch <- checkBlacklist(settings, isoCode)
			return
		}
	}
	ch <- Dunno
}

// checkWhois tries to check the client's country through a whois query for the
// client's name or IP address.
func checkWhois(settings Settings, target string, ch chan string) {
	if len(target) == 0 {
		ch <- Dunno
		return
	}
	log := settings.Syslog
	log.Debug(
		fmt.Sprintf(
			"Guessing country for %s through %s",
			target,
			settings.Configuration.WhoisProgram,
		),
	)
	var countries []string
	ip := net.ParseIP(target)
	// If it's an IP address
	if ip != nil {
		countries = queryResource(settings, target)
	} else {
		settings.Syslog.Debug(fmt.Sprintf("Checking whois records for domain name: %s", target))
		parts := strings.Split(target, ".")
		if len(parts) >= 2 {
			domain := parts[len(parts)-1]          // We pick the last domain part
			for i := len(parts) - 2; i >= 0; i-- { // We pick each part after that from the end
				domain = parts[i] + "." + domain // and we build a possible domain
				countries = queryResource(settings, domain)
				// Ideally there is only one valid domain we should
				// use. So if we got any country from any of the
				// guesses, there is no need to try other combinations.
				if len(countries) > 0 {
					break
				}
			}
		}
	}
	ch <- checkBlacklist(settings, countries...)
	return
}



// isWhitelisted compares a fqdn to a list of whitelisted suffixes.
func isWhitelisted(fqdn string, whitelist []string) bool {
	target := strings.ToLower(strings.TrimSpace(fqdn))
	if len(target) == 0 {
		return false
	}
	for _, allowed := range whitelist {
		match := strings.HasSuffix(target, allowed)
		if match == true {
			return true
		}
	}
	return false
}

// checkTopLevelDomain checks if the client name or the sender address'
// top-level domain can be read as a country code.
func checkTopLevelDomain(settings Settings, target string, ch chan string) {
	if len(target) <= 2 {
		ch <- Dunno
		return
	}
	settings.Syslog.Debug(
		fmt.Sprintf(
			"Guessing country of top-level domain in %q",
			target,
		),
	)
	last := strings.LastIndex(target, ".")
	if last > 0 {
		top := strings.Trim(target[last:], ".")
		if len(top) == 2 {
			top = strings.ToUpper(top)
			settings.Syslog.Debug(
				fmt.Sprintf(
					"Checking if top-level domain %s is the isoCode of a blacklisted country",
					top,
				),
			)
			ch <- checkBlacklist(settings, top)
			return
		}
	}
	ch <- Dunno
}

// queryResource queries the whois record of a specific resource.
func queryResource(settings Settings, resource string) []string {
	var countries []string
	if settings.WhoisClient != nil && len(resource) > 0 {
		log := settings.Syslog
		whoisResponse := settings.WhoisClient.Query(resource)
		if !whoisResponse.IsValid() {
			log.Debug(
				fmt.Sprintf(
					"No result querying whois for resource %s: %s",
					resource, whoisResponse.Error.Error(),
				),
			)
		} else {
			countries = whoisResponse.CountryCodes
			log.Debug(
				fmt.Sprintf(
					"Whois lookup for %s resulted in the following countries: %q",
					resource,
					whoisResponse.CountryCodes,
				),
			)
		}
	}
	return countries
}

// checkBlacklist checks if any ISO country codes is blacklisted and, in case,
// returns a REJECT string.
func checkBlacklist(settings Settings, isoCodes ...string) string {
	log := settings.Syslog
	for _, isoCode := range isoCodes {
		if len(isoCode) > 0 {
			blacklist := settings.BlackList
			log.Debug(
				fmt.Sprintf("checking ISO country code %s against blacklist %q", isoCode, blacklist),
			)
			isoCode = strings.ToUpper(isoCode) // The blacklist elements are all Uppercase (see config parsing code)
			for _, blacklistedIsoCode := range settings.BlackList {
				if isoCode == blacklistedIsoCode {
					log.Debug(fmt.Sprintf("ISO country code %s is blacklisted", isoCode))
					return Reject
				}
			}
			log.Debug(fmt.Sprintf("ISO country code %s is not blacklisted", isoCode))
		}
	}
	return Dunno
}

// geoIP2Lookup looks up an IP address in a GeoIP2 database.
func geoIP2Lookup(settings Settings, ip net.IP) string {
	var isoCode string
	log := settings.Syslog
	database := settings.GeoIP2Database
	if ip != nil && len(database) > 0 {
		log.Debug(fmt.Sprintf("looking up country of address %s from GeoIP2 database %s", ip.String(), database))
		db, err := geoip2.Open(database)
		if err != nil {
			log.Err(
				fmt.Sprintf(
					"failed to open GeoIP2 database: %s", err.Error(),
				),
			)
		} else {
			defer db.Close()
			record, err := db.Country(ip)
			if err != nil {
				log.Err(
					fmt.Sprintf(
						"failed to retrieve country from GeoIP2 database: %s",
						err.Error(),
					),
				)
			} else {
				isoCode = record.Country.IsoCode
				if len(isoCode) > 0 {
					log.Debug(
						fmt.Sprintf("GeoIP2 database lists address %s as from country %s", ip.String(), isoCode),
					)
				} else {
					log.Info(
						fmt.Sprintf(
							"no country found for address %s", ip.String(),
						),
					)
				}
			}
		}
	}
	return isoCode
}

// split a very simple wrapper to split a string in two.
func split(line string, separator string) (key string, value string) {
	parts := strings.SplitN(line, separator, 2)
	// I am only interested in lines containing the separator
	if len(parts) == 2 {
		key = strings.TrimSpace(parts[0])
		value = strings.TrimSpace(parts[1])
	}
	return
}
