---
layout: post
title: "Docker Container Scanning with Trivy"
---

How to scan docker containers for vulnerabilities using [trivy](https://github.com/aquasecurity/trivy).

<!-- more -->

## Installing Trivy

Head over to trivy [GitHub](https://github.com/aquasecurity/trivy) repo where install instuctions for diffent flavours of OS is listed. I installed trivy on Ubuntu 18.04 with the following commands.

```
$ sudo apt-get install rpm
$ wget https://github.com/aquasecurity/trivy/releases/download/v0.1.6/trivy_0.1.6_Linux-64bit.deb
$ sudo dpkg -i trivy_0.1.6_Linux-64bit.deb
```

Once installation is finished, trivy command will be available in the command line.

```
$ trivy -h
NAME:
  trivy - A simple and comprehensive vulnerability scanner for containers
USAGE:
  trivy [options] image_name
VERSION:
  0.1.6
OPTIONS:
  --format value, -f value    format (table, json) (default: "table")
  --input value, -i value     input file path instead of image name
  --severity value, -s value  severities of vulnerabilities to be displayed (comma separated) (default: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
  --output value, -o value    output file name
  --exit-code value           Exit code when vulnerabilities were found (default: 0)
  --skip-update               skip db update
  --only-update value         update db only specified distribution (comma separated)
  --reset                     remove all caches and database
  --clear-cache, -c           clear image caches
  --quiet, -q                 suppress progress bar and log output
  --no-progress               suppress progress bar
  --ignore-unfixed            display only fixed vulnerabilities
  --refresh                   refresh DB (usually used after version update of trivy)
  --auto-refresh              refresh DB automatically when updating version of trivy
  --debug, -d                 debug mode
  --vuln-type value           comma-separated list of vulnerability types (os,library) (default: "os,library")
  --cache-dir value           cache directory (default: "/home/observer/.cache/trivy")
  --help, -h                  show help
  --version, -v               print the version
```

An image can be scanned as follows:
```
$ trivy [YOUR_IMAGE_NAME]
```

### Docker Container Scanning
#### 1. Login to Docker Registry
```
$ sudo docker login <docker registry>

example: 
$ sudo docker login registry.gitlab.com
```
Note: provide username and password when prompted. Once login is successfull, `Login Succeeded` output can be seen in terminal.

> This method of login stores unencrypted password in ~/.docker/config.json

#### 2. Pull Docker Container
```
$ sudo docker pull <image source tag>

example:
$ sudo docker pull registry.gitlab.com/sekiro/sword-saint:isshin-ashina-1.0
```
#### 3. Scan The Container using Trivy
```
$ sudo trivy <image source tag>

example:
$ sudo trivy registry.gitlab.com/sekiro/sword-saint:isshin-ashina-1.0
```
