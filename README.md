# policyd-geoip
Small GoLang program to use MaxMind's GeoIP2 database (and, optionally, Whois lookups and top domain guessing) for [Postfix policy delegation](http://www.postfix.org/SMTPD_POLICY_README.html).

Whois processing is time consuming, on my systems it adds about two seconds to the processing.

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

If you want to be able to also process the sender address you need to use the policy in a later step of the Postfix process, after the client has sent the `MAIL FROM` command, for example `smtpd_sender_restrictions`.

## YAML configuration example
```
# Additional text to add to the REJECT message
reject_message: "Not interested"
# Should the program print debug information
debug: false
# ISO codes of countries not allowed to access the Postfix server
blacklist:
  - SE # Sweden
  - US # USA
# Special codes used by Maxmind:
  - A1 # Anonymous Proxy
  - A2 # Satellite Provider
  - O1 # Other Country
# Location of the Maxmind's Geoip2 database
geoip2_database: "/usr/share/GeoIP/GeoLite2-Country.mmdb"
# Domain that allows the client to skip the country check
whitelist:
  - google.com
# All logs are sent to Syslog (the program is not supposed to be run in console)
syslog_facility: mail
syslog_tag: policyd-geoip2
# Optionally can use data from Whois to guess the country
# Omit to just use geoip2 database.
whois_program: /usr/bin/whois
```
