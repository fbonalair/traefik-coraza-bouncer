![GitHub](https://img.shields.io/github/license/fbonalair/traefik-coraza-bouncer)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/fbonalair/traefik-coraza-bouncer)
[![Go Report Card](https://goreportcard.com/badge/github.com/fbonalair/traefik-coraza-bouncer)](https://goreportcard.com/report/github.com/fbonalair/traefik-coraza-bouncer)
[![Maintainability](https://api.codeclimate.com/v1/badges/ee4236396b2c5ccbc7c0/maintainability)](https://codeclimate.com/github/fbonalair/traefik-coraza-bouncer/maintainability)
[![ci](https://github.com/fbonalair/traefik-coraza-bouncer/actions/workflows/main.yml/badge.svg)](https://github.com/fbonalair/traefik-coraza-bouncer/actions/workflows/main.yml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/fbonalair/traefik-coraza-bouncer)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/fbonalair/traefik-coraza-bouncer)

# traefik-coraza-bouncer
A http service to verify request and bounce them according to Coraza WAF

# Description
This repository aim to implement a [Coraza](https://coraza.io/) bouncer for the router [Traefik](https://doc.traefik.io/traefik/) to protect your services.
For this it leverages [Traefik v2 ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) to get request info and Coraza to check for interrupt.
If an interrupt appear, this bouncer will answer with a http code 403 response. Otherwise, request will continue as usual.   
One important thing to note though, the request body will **NOT** be taken into consideration for the interrupt. This a limitation of the ForwardAuth middleware.   


# Demo
## Prerequisites
[Docker](https://docs.docker.com/get-docker/) and [Docker-compose](https://docs.docker.com/compose/install/) installed.   
You can use the docker-compose in the examples' folder as a starting point.
Through traefik it exposes the whoami countainer on port 80, with the bouncer accepting and rejecting client IP.   
Launch your all services except the bouncer with the follow commands:
```bash
git clone https://github.com/fbonalair/traefik-crowdsec-bouncer.git && \
  cd traefik-crowdsec-bouncer/examples && \
  docker-compose up -d traefik crowdsec whoami 
```


## Procedure
???

# Usage
For now, this web service is mainly fought to be used as a container.   
If you need to build from source, get some inspiration from the Dockerfile.

## Prerequisites
The container is available on docker as image `fbonalair/traefik-coraza-bouncer`. Host it as you see fit, though it must be accessible by Traefik.   
Follow  [traefik v2 ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) documentation to create a forwardAuth middle pointing to your bouncer host.   

## Configuration
The webservice configuration is made via environment variables:

* `PORT`                                - Change listening port of web server. Default listen on 8080
* `GIN_MODE`                            - By default, run app in "debug" mode. Set it to "release" in production
* `BOUNCER_SEC_RULES`                   - WAF rules to apply by Coraza in [Seclang syntax](https://coraza.io/docs/seclang/syntax/). i.e. `SecRule REMOTE_ADDR \"@rx .*\" \"id:1,phase:1,deny,status:403\"` to deny everything
* `BOUNCER_SEC_RULES.CUSTOM_PATH`       - Path to file containing WAF rules to apply by Coraza in [Seclang syntax](https://coraza.io/docs/seclang/syntax/). i.e. `/etc/waf/custom-ruleset/myrules.conf`. Default to `/etc/bouncer/rules/*` to include all files in this directory (note the *)
* `BOUNCER_SEC_RULES.RECOMMENDED`       - Boolean to download and applying coraza recommended configuration. Expected value are `true` or `false`, case-sensitive. Default to `true`.
* `BOUNCER_SEC_RULES.OWASP`             - Boolean to download and applying top [10 OWASP core ruleset](https://coraza.io/docs/tutorials/coreruleset/). Expected value are `true` or `false`, case-sensitive. Default to `true`.

## Exposed routes
The webservice exposes some routes:

* GET `/api/v1/forwardAuth`             - Main route to be used by Traefik: use Coraza with information taken from headers
* GET `/api/v1/ping`                    - Simple health route that respond pong with http 200
* GET `/api/v1/healthz`                 - Another health route that query Coraza with some default values
* GET `/api/v1/metrics`                 - Prometheus route to scrap metrics

# Contribution
Feel free to leave an issue if you found a bug or need a new feature.
TODO:
- Communication with crowdsec: Hosting syslog server to send mod security log
  - suggested communication https://discourse.crowdsec.net/t/communication-between-crowdsec-and-a-waf/517
  - syslog server with https://github.com/mcuadros/go-syslog

## Local development
Assuming Linux, follow those command to build the needed C bindings:
```
  git clone https://github.com/libinjection/libinjection
  gcc -std=c99 -Wall -Werror -fpic -c libinjection/src/libinjection_sqli.c -o libinjection/libinjection_sqli.o
  gcc -std=c99 -Wall -Werror -fpic -c libinjection/src/libinjection_xss.c -o libinjection/libinjection_xss.o
  gcc -std=c99 -Wall -Werror -fpic -c libinjection/src/libinjection_html5.c -o libinjection/libinjection_html5.o
  gcc -dynamiclib -shared -o libinjection/libinjection.so libinjection/libinjection_sqli.o libinjection/libinjection_xss.o libinjection/libinjection_html5.o
  sudo cp libinjection/*.so /usr/local/lib
  sudo cp libinjection/*.o /usr/local/lib
  sudo cp libinjection/src/*.h /usr/local/include/
  sudo chmod 444 /usr/local/include/libinjection*
  sudo ldconfig
```
You might also need libpcre-devel: `sudo apt install libpcre++-dev -y` depending on your distro.   
You should set your environment var `CONFIG_PATH` to the absolute path of file `configs/config.yaml`