package main

import (
	"bufio"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
	"strings"
)

const  (

dnsRegexAll = `(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])`
dnsRegex = `(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.){2,}([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])`
ipRegex = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.` +
		`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.` +
		`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.` +
		`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

impacketRegexDns = `@?(` + dnsRegex + `$)`
impacketRegexIP = `@?(` + ipRegex + `$)`
impacketRegexCreds = `^(.{1,}(:.{1,})?)@`


xfreerdpRegexHost = `\/v:(` + dnsRegexAll + `$)`
xfreerdpRegexDomain = `\/d:(` + dnsRegexAll + `$)`
xfreerdpRegexIP = `\/v:(` + ipRegex + `$)`

winrmRegexDns = `^(` + dnsRegex + `$)`
winrmRegexIP = `^(` + ipRegex + `$)`

rdesktopRegexDnsFull = `^(` + dnsRegexAll + `@` + dnsRegexAll + `$)`
rdesktopRegexDns = `^((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$)`
rdesktopRegexIP = `^(` + ipRegex + `$)`

)

func Usage() {
	fmt.Printf("Usage: %s <raw_log_file>", os.Args[0])
	flag.PrintDefaults()
}

func getTool(l string) string {
	if strings.Contains(l, "wmiexec") {
		return "wmiexec"
	} else if strings.Contains(l, "smbexec") {
		return "smbexec"
	} else if strings.Contains(l, "smbexec") {
		return "smbexec"
	} else if strings.Contains(l, "atexec") {
		return "atexec"
	} else if strings.Contains(l, "psexec") {
		return "psexec"
	} else if strings.Contains(l, "evil-winrm") {
		return "evil-winrm"
	} else if strings.Contains(l, "xfreerdp") {
		return "xfreerdp"
	} else if strings.Contains(l, "secretsdump") {
		return "secretsdump"
	} else if strings.Contains(l, "rdesktop") {
		return "rdesktop"
	} else if strings.Contains(l, "smbclient") {
		return "smbclient"
	} else if strings.Contains(l, "rpcclient") {
		return "rpcclient"
	} else {
		return ""
	}
}

func getTarget (line string,tool string) (host,domain string) {
	lineSlice := strings.Split(line," ")
	if (tool == "wmiexec") || (tool == "smbclient") || (tool == "smbexec") || (tool == "atexec") || (tool == "secretsdump"){
		for _,s := range lineSlice {

			// Check IP regexp first
			r := regexp.MustCompile(impacketRegexIP)
			match := r.FindStringSubmatch(s)
			if match != nil {
				ip := match[1]
				domain = ""
				host = ip
			}

			// Check FQDN regexp second
			r = regexp.MustCompile(impacketRegexDns)
			match = r.FindStringSubmatch(s)
			if (match != nil) && (!strings.Contains(s,"KRB5CCNAME=")) && (host == "") {
				fqdn := match[1]
				domain = strings.Join(strings.Split(fqdn,".")[1:],".")
				host = strings.Split(fqdn,".")[0]
			}
		}
	} else if tool == "xfreerdp" {
		for _,s := range lineSlice {

			// Check IP regexp first
			r := regexp.MustCompile(xfreerdpRegexIP)
			match := r.FindStringSubmatch(s)
			if match != nil {
				ip := match[1]
				domain = ""
				host = ip
			}

			// Check host or FQDN regexp second
			r = regexp.MustCompile(xfreerdpRegexHost)
			match = r.FindStringSubmatch(s)
			if (match != nil) && (host == "")  {
				fqdn := strings.Split(match[1],".")
				if len(fqdn) > 1 {
					domain = strings.Join(fqdn[1:],".")
					host = fqdn[0]
				} else {
					host = fqdn[0]
				}
			}

			// Check domain regexp
			r = regexp.MustCompile(xfreerdpRegexDomain)
			match = r.FindStringSubmatch(s)
			if match != nil {
				domain = match[1]
			}
		}
	} else if tool == "evil-winrm" {
		for i,s := range lineSlice {

			// Check IP regexp first
			r := regexp.MustCompile(winrmRegexIP)
			match := r.FindStringSubmatch(s)
			if match != nil {
				ip := match[1]
				host = ip
			}

			// Check FQDN regexp second
			r = regexp.MustCompile(winrmRegexDns)
			match = r.FindStringSubmatch(s)
			if (match != nil) && (host == "") {
				fqdn := match[1]
				domain = strings.Join(strings.Split(fqdn,".")[1:],".")
				host = strings.Split(fqdn,".")[0]
			}

			// Check -i param
			if s == "-i" {
				host = lineSlice[i+1]
			}

		}
		return

	} else if tool == "rdesktop" {
		for i,s := range lineSlice {
			// Check IP regexp first
			r := regexp.MustCompile(rdesktopRegexIP)
			match := r.FindStringSubmatch(s)
			if match != nil {
				ip := match[1]
				host = ip
			}

			// Check FQDN regexp second
			r = regexp.MustCompile(rdesktopRegexDnsFull)
			match = r.FindStringSubmatch(s)
			if (match != nil) && (host == "") {
				fqdn := match[1]
				domain = strings.Split(fqdn,"@")[1]
				host = strings.Split(fqdn,"@")[0]
				host = strings.Split(host,".")[0]
			}

			// Check if -d (domain) parameter set
			if s == "-d" {
				domain = lineSlice[i+1]
			}

			// Check default FQDN in string
			r = regexp.MustCompile(rdesktopRegexDns)
			match = r.FindStringSubmatch(s)
			if (host == "") && (i > 0) && (match != nil) && (match[1] != "proxychains") && (match[1] != "rdesktop") && (lineSlice[i-1] != "-d") && (lineSlice[i-1] != "-u"){
				fqdn := strings.Split(match[1],".")
				if len(fqdn) > 1 {
					domain = strings.Join(fqdn[1:],".")
				}
				host = fqdn[0]
			}
		}
	}
	return
}

func getCreds (lineSlice []string,tool string) (login, pass string) {
	if (tool == "wmiexec") || (tool == "smbclient") || (tool == "smbexec") || (tool == "atexec") || (tool == "secretsdump"){
		for i,s := range lineSlice {
			r := regexp.MustCompile(impacketRegexCreds)
			match := r.FindStringSubmatch(s)
			if match != nil {
				creds := strings.Split(match[1], ":")
				if len(creds) > 1 {
					login = creds[0]
					pass = creds[1]
				} else {
					login = creds[0]
				}

			}
			if s == "-k" {
				login = "kerberos"
			}
			if s == "-hashes" {
				pass = lineSlice[i+1]
			}

		}
	} else if tool == "xfreerdp" {
		for _,s := range lineSlice {
			if strings.Contains(s,"/u:") {
				login = strings.Split(s,":")[1]
			}
			if strings.Contains(s,"/p:") {
				pass = strings.Split(s,":")[1]
			}
			if strings.Contains(s,"/pth:") {
				pass = strings.Split(s,":")[1]
			}
	}
	} else if tool == "evil-winrm" {
		for i,s := range lineSlice {
			if s == "-u" {
				login = lineSlice[i+1]
			}
			if s == "-p" {
				pass = lineSlice[i+1]
			}
		}
	} else if tool == "rdesktop" {
		for i,s := range lineSlice {
			if s == "-u" {
				login = lineSlice[i+1]
			}
		}
	}
	return
}

func main() {
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatal("Specify raw log file path")
	}
	rawFilePath := flag.Arg(0)
	f, err := os.Open(rawFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rawLine := scanner.Text()
		rawLineSlice := strings.Split(rawLine, " ")
		date := rawLineSlice[0]
		time := rawLineSlice[1]
		tool := getTool(rawLine)
		host,domain := getTarget(rawLine,tool)
		user,pass := getCreds(rawLineSlice,tool)

		fmt.Printf("%s %s,%s,%s,%s,%s,%s\n",date,time,tool,domain,user,pass,host)


	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
