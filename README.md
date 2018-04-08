# policyd-geoip
Small GoLang program to use MaxMind's GeoIP2 database for Postfix's policy.

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
# Full path to the GeoIP2 database to use
geoip2_database: /usr/share/GeoIP/GeoLite2-Country.mmdb
# Time interval for refreshing configuration
refresh_interval: 10m
```
