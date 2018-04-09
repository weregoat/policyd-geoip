# policyd-geoip
Small GoLang program to use MaxMind's GeoIP2 database for [Postfix policy delegation](http://www.postfix.org/SMTPD_POLICY_README.html)

## How to use

### Add a service to Postfix `master.cf`:
```
# Geoip
policy-geoip unix -	n	n	-	-	spawn
  user=nobody argv=/path/to/bin/policyd-geoip --configuration /path/to/policyd-geoip.yaml
```

`--configuration` flag is optional; program defaults to use `/usr/local/etc/policyd-geoip.yaml`.

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
---
# Debug log to syslog
debug: true
# ISO 3166-1 alpha2 codes for country to blacklist
blacklist:
  - A1 # Maxmind own code for anonymous proxies
  - A2 # Maxmind own code for satellite providers
  - O1 # Maxmind own code for other countries
#  - SE # Sweden
   #  Etc. Etc.
# Whitelisted clients (matched as prefix)
whitelist:
  - google.com
# Full path to the GeoIP2 database to use
geoip2_database: /usr/share/GeoIP/GeoLite2-Country.mmdb
# Refresh the configuration if the previous policy request
# was older than this interval
refresh_interval: 10m
```
