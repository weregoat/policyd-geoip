# policyd-geoip
Small GoLang program to use MaxMind's GeoIP2 database for [Postfix policy delegation](http://www.postfix.org/SMTPD_POLICY_README.html)

## How to use

### Add a service to Postfix `master.cf`:
```
# Geoip
policy-geoip unix -	n	n	-	-	spawn
  user=nobody argv=/path/to/bin/policyd-geoip --configuration /path/to/policyd-geoip.yaml
```

If `--configuration` flag is omitted, the program tries to access `/etc/policyd-geoip.yaml`.

### Then you can use the policy like so in `main.cf`:
```
smtpd_..._restrictions =
  ...
  check_policy_service unix:private/policy-geoip
  ...

policy-geoip_time_limit = 3600
```

## YAML configuration example
```
# Debug log to syslog
debug: true
# ISO 3166-1 alpha2 codes for country to blacklist
blacklist:
  - A1 # Maxmind own code for anonymous proxies
  - A2 # Maxmind own code for satellite providers
  - O1 # Maxmind own code for other countries
#  - SE # Sweden
   #  Etc. Etc.
# Whitelisted clients (matched at the end)
whitelist:
  - google.com
# Full path to the GeoIP2 database to use
geoip2_database: /usr/share/GeoIP/GeoLite2-Country.mmdb
# Refresh the configuration if the previous policy request
# was older than this interval
refresh_interval: 10m

# Syslog options
# Be aware that if any of the following options is rejected, the default ones 
# (mail, policyd-geoip) will be used instead. 
# That includes the error/warning messages and errors that block the parsing of
# the configuation.

# Name of the syslog facility
# Only mail,auth,authpriv,user,daemon,local0 ... local7 will be accepted
syslog_facility: mail
# Syslog tag 
syslog_tag: policyd-geoip

# Whois lookups
# Optional, it will be used only in case the GeoIP results in a pass and one
# of the server or program field is not empty.
whois:
  # Specify the initial server to use for Whois lookups
  server: whois.iana.org
  # Specify the path to the program to use to query for whois entry
  program: /usr/local/bin
  # If both are set, the program will take precedence  and the server will only be used 
  # in case of no results from the program as a fallback.
```
