package main

import (
	"net/http"
	"net/http/httputil"
	"time"
)

type HTTPProxy struct {
	proxy  httputil.ReverseProxy
	rules  *ForwardRules
	listen string
}

func NewHTTPProxy(r *ForwardRules, listen string) *HTTPProxy {
	return &HTTPProxy{
		proxy: httputil.ReverseProxy{
			Director: func(h *http.Request) {
				h.URL.Scheme = "http"
				h.URL.Host = h.Host
			},
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				MaxConnsPerHost:       0,
				IdleConnTimeout:       time.Second * 30,
				ResponseHeaderTimeout: time.Second * 15,
				ExpectContinueTimeout: time.Second * 15,
				Dial:                  dialer.Dial,
			},
		},
		rules:  r,
		listen: listen,
	}
}
func (c *HTTPProxy) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if !c.rules.IsHostAllowed(r.Host) {
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte("Forbidden"))
			return
		}
		LogAccess("http", r.RemoteAddr, r.Host)
		c.proxy.ServeHTTP(rw, r)
	})
	logger.Infof("Initialize ok, start serving http at %v", c.listen)
	go func() {
		if err := http.ListenAndServe(c.listen, mux); err != nil {
			logger.Fatal("Start http server failed, err:", err)
		}
	}()
	return nil
}
