package main

import (
	"net"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var (
	dialer net.Dialer
)

func main() {
	setupConfig()
	setupLog()
	startDefaultHTTPServer()
	rules := NewForwardRules()
	dialer = net.Dialer{}
	if viper.GetString("global.outip") != "" {
		ip := net.ParseIP(viper.GetString("global.outip"))
		if ip == nil {
			logger.Fatalf("Invalid outgoing IP %s specified", viper.GetString("global.outip"))
			return
		}
		dialer.LocalAddr = &net.TCPAddr{
			IP:   ip,
			Port: 0,
			Zone: "",
		}
	}
	dialer.Timeout = time.Second * 15

	hasSomethingToDo := false
	for _, s := range strings.Split(viper.GetString("https.listen"), ",") {
		s = strings.Trim(s, " ")
		NewHTTPSProxy(rules, s).Start()
		hasSomethingToDo = true
	}
	for _, s := range strings.Split(viper.GetString("http.listen"), ",") {
		s = strings.Trim(s, " ")
		NewHTTPProxy(rules, s).Start()
		hasSomethingToDo = true
	}

	if !hasSomethingToDo {
		logger.Errorf("Neither http nor https server configured, quitting...")
		return
	}
	// sleep forever
	for {
		time.Sleep(time.Duration(1<<63 - 1))
	}
}
