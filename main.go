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

	start := time.Now()
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
	client := newClient()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		response := Dunno
		begin := time.Now()
		line := scanner.Text()
		settings.Syslog.Debug(fmt.Sprintf("Read line '%s' from stdin", line))
		if strings.Contains(line, "=") {
			parseLine(&client, line, settings.Syslog)
		}
		// End of input
		if line == "" {
			if isWhitelisted(client.Name, settings.WhiteList, settings.Syslog) {
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
					fmt.Sprintf("Client %s is not blacklisted",
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
			elapsed := time.Since(start)
			if elapsed.Minutes() >= settings.RefreshInterval.Minutes() {
				settings.Syslog.Debug("refreshing configuration")
				newSettings, err := readConfig(*configuration)
				if err == nil {
					settings = newSettings
				} else {
					settings.Syslog.Err(
						fmt.Sprintf(
							"Ignoring new configuration because of error: %s",
							err.Error(),
						),
					)
				}
				start = time.Now()
			}
			print(action)
			client = newClient()
		}
	}
	if err := scanner.Err(); err != nil {
		settings.Syslog.Err(err.Error())
		fmt.Fprintln(os.Stderr, "Reading standard input:", err)
		os.Exit(1)
	}

}

// read the configuration
func readConfig(path string) (Settings, error) {
	var settings Settings
	config, err := loadConfiguration(path)
	if err != nil {
		return settings, err
	}
	settings, err = parseConfiguration(config)
	for _, setting := range settings.Show() {
		settings.Syslog.Debug(setting)
	}
	return settings, err
}

// Print the result as action. Notice action should be followed by an empty
// line.
func print(action string) {
	writer := bufio.NewWriter(os.Stdout)
	writer.WriteString(fmt.Sprintf("%s\n\n", action))
	writer.Flush()
}

// Wraps the various checks for the client.
func checkClient(settings Settings, client Client) string {
	checkGeoIP2(settings, &client) // Check the IP address using Geoip2
	checkTopLevelDomain(settings, &client)
	checkWhois(settings, &client) // Try to guess country through Whois
	if len(client.Status) == 0 {
		// If we could not evaluate the client in any way
		client.Status = Defer
	}
	return client.Status
}

// Check the client against the GeoIP2 database.
func checkGeoIP2(settings Settings, client *Client) {
	if client.Status != Reject {
		if client.IP != nil {
			isoCode := geoIP2Lookup(settings, client.IP)
			if len(isoCode) == 2 {
				client.Status = checkBlacklist(settings, isoCode)
			}
		}
	}
}

// Check the client name and IP through the whois program.
func checkWhois(settings Settings, client *Client) {
	if client.Status != Reject {
		if settings.WhoisClient != nil {
			settings.Syslog.Debug(
				fmt.Sprintf(
					"Guessing country for client %s through %s",
					client.String(),
					settings.Configuration.WhoisProgram,
				),
			)
			if client.IP != nil {
				if checkResource(settings, client.IP.String()) == Reject {
					client.Status = Reject
					return
				}
			}
			if len(client.Name) > 2 {
				parts := strings.Split(client.Name, ".")
				// https://en.wikipedia.org/wiki/Fully_qualified_domain_name
				// The FQDN should have been split into a hostname parts[0]
				// and the domain parts[1:]
				// Otherwise is not really something we should have got as
				// client_name (because it's not FQDN)
				if len(parts) > 2 {
					domain := parts[len(parts)-1]         // We pick the last domain part
					for i := len(parts) - 2; i > 0; i-- { // We pick each part after that from the end
						domain = parts[i] + "." + domain // and we build a possible domain
						client.Status = checkResource(settings, domain)
						if client.Status != Dunno {
							// Either we failed to look it up
							// or is blacklisted.
							// In both cases we break up
							return
						}
					}
				}
			}
		}
	}
}

// Check if the client name is whitelisted.
func isWhitelisted(clientName string, whitelistedClients []string, log Syslog) bool {
	allow := false
	for _, allowedClient := range whitelistedClients {
		match := strings.HasSuffix(strings.ToLower(strings.TrimSpace(clientName)), allowedClient)
		if match == true {
			log.Info(
				fmt.Sprintf(
					"Client %s is whitelisted under %s",
					clientName, allowedClient,
				),
			)
			allow = true
			break
		}
	}
	return allow
}

// Check if the client name or the sender address' top-level domain can be
// used to guess a country.
func checkTopLevelDomain(settings Settings, client *Client) {
	if client.Status != Reject {
		var names []string
		if len(client.Name) > 2 {
			names = add(names, client.Name)
		}
		if len(client.Sender) > 0 && settings.CheckSenderAddress {
			names = add(names, client.Sender)
		}
		if len(names) > 0 {
			settings.Syslog.Debug(
				fmt.Sprintf(
					"Guessing country of top-level domains %q",
					names,
				),
			)
			for _, name := range names {
				last := strings.LastIndex(name, ".")
				if last > 0 {
					top := strings.Trim(name[last:], ".")
					if len(top) == 2 {
						top = strings.ToUpper(top)
						settings.Syslog.Debug(
							fmt.Sprintf(
								"Checking if top-level domain %s is the isoCode of a blacklisted country",
								top,
							),
						)
						if checkBlacklist(settings, top) == Reject {
							client.Status = Reject
							return
						}
					}
				}
			}
		}
	}
}

// Check the whois record of a specific resource.
func checkResource(settings Settings, resource string) string {
	result := Dunno // Default is not blacklisted
	if settings.WhoisClient != nil && len(resource) > 0 {
		log := settings.Syslog
		whoisResponse := settings.WhoisClient.Query(resource)
		if whoisResponse.Error != nil {
			log.Warning(
				fmt.Sprintf(
					"No result querying whois for resource %s: %s",
					resource, whoisResponse.Error.Error(),
				),
			)
		} else {
			log.Debug(
				fmt.Sprintf(
					"Whois lookup for %s resulted in the following countries: %q",
					resource,
					whoisResponse.CountryCodes,
				),
			)
			for _, isoCode := range whoisResponse.CountryCodes {
				result = checkBlacklist(settings, isoCode)
				// Any of the country being blacklisted is enough
				if result == Reject {
					return result
				}
			}
		}
	}
	return result
}

// Check if an ISO country code is in the blacklist.
func checkBlacklist(settings Settings, isoCode string) string {
	log := settings.Syslog
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
	} else {
		log.Notice("no ISO country code passed to function")
	}
	return Dunno
}

// geoIP2Lookup
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

// Parses the line with the attributes from Postfix.
func parseLine(client *Client, line string, log Syslog) {
	pos := strings.Index(line, "=")
	if pos <= 0 {
		return
	}
	key := line[:pos]
	value := strings.TrimSpace(line[pos+1:])
	if len(value) > 0 {
		switch key {
		case "client_address":
			client.IP = net.ParseIP(value)
		case "client_name", "reverse_client_name":
			if strings.ToLower(value) != "unknown" &&
				len(client.Name) == 0 {
				client.Name = value
			}
		case "sender":
			client.Sender = value
		}
	}
}

func add(original []string, element string) []string {
	if len(element) > 0 {
		e := strings.ToLower(element)
		for _, o := range original {
			if e == strings.ToLower(o) {
				return original
			}
		}
		original = append(original, element)
	}
	return original
}
