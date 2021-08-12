package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"
)

type BoolMap map[string]bool

type ForwardRules struct {
	rules       [2]*BoolMap
	index       uint32
	updateLock  sync.Mutex
	cache       sync.Map
	passThrough bool
}

func NewForwardRules() *ForwardRules {
	ret := &ForwardRules{
		rules:       [2]*BoolMap{},
		index:       0,
		updateLock:  sync.Mutex{},
		cache:       sync.Map{},
		passThrough: false,
	}
	if err := ret.Load(); err != nil {
		logger.Fatalf("Load rules failed, err %v", err)
		return nil
	}
	ret.passThrough = viper.GetBool("client.passthrough")

	http.HandleFunc("/config/get", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ret.GetJson())
	})
	http.HandleFunc("/config/update", func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		err := ret.PutJson(body)
		if err != nil {
			logger.Warnf("Unable to set host config, error %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("set hosts config error: %v", err)))
		} else {
			err := ret.Save()
			if err != nil {
				logger.Warn("save config failed, %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("save config error: %v", err)))
			} else {
				logger.Info("config updated and saved successfully")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}
		}
	})
	return ret
}

func (f *ForwardRules) setRules(rules *BoolMap) {
	f.updateLock.Lock()
	defer f.updateLock.Unlock()
	var useIndex uint32
	oldindex := f.index
	if oldindex == 0 {
		useIndex = 1
	} else {
		useIndex = 0
	}
	f.rules[useIndex] = rules

	atomic.StoreUint32(&f.index, uint32(useIndex))

	f.rules[oldindex] = &BoolMap{}

	f.cache.Range(func(key interface{}, value interface{}) bool {
		f.cache.Delete(key)
		return true
	})
}

func (f *ForwardRules) IsHostAllowedByRule(host string) bool {
	host = strings.Trim(strings.ToLower(host), ".")
	if r, ok := f.cache.Load(host); ok {
		return r.(bool)
	}
	rules := f.rules[f.index]
	if r, ok := (*rules)[host]; ok {
		f.cache.Store(host, r)
		return r
	}
	hostlen := len(host)
	// FIXME: this would fail if there is no '.' in the string, but it doesn't matter
	for i := 0; i < hostlen-1; i++ {
		if host[i] == '.' {
			if r, ok := (*rules)[host[i+1:]]; ok {
				f.cache.Store(host, r)
				return r
			}
		}
	}
	// Negative cache is not necessary since DNS won't resolve to sniproxy
	return false
}

func (f *ForwardRules) GetJson() []byte {
	rules := f.rules[f.index]
	newmap := map[string]string{}
	for k := range *rules {
		newmap[k] = ""
	}
	ret, _ := json.MarshalIndent(newmap, "", "  ")
	return ret
}

func (f *ForwardRules) PutJson(data []byte) error {
	var test map[string]string
	if err := json.Unmarshal(data, &test); err != nil {
		logger.Warnf("Unable to parse json, error %v", err)
		return err
	}
	rules := BoolMap{}
	for k := range test {
		k = strings.ToLower(k)
		rules[k] = true
	}
	f.setRules(&rules)
	return nil
}

func (f *ForwardRules) IsHostAllowed(remoteHost string) bool {
	return f.passThrough || f.IsHostAllowedByRule(remoteHost)
}

func (f *ForwardRules) RunConnection(clientConn *tlsConn, remoteHost string, pendingMessage *tlsMessage) error {
	defer clientConn.conn.Close()
	if !f.passThrough && !f.IsHostAllowedByRule(remoteHost) {
		return errTargetRejected
	}
	if _, _, err := net.SplitHostPort(remoteHost); err != nil {
		remoteHost = net.JoinHostPort(remoteHost, "443")
	}
	conn, err := net.DialTimeout("tcp", remoteHost, 5*time.Second)
	if err != nil {
		logger.Infow("remote connect fail", "remote", remoteHost, "err", err)
		return err
	}
	defer conn.Close()
	serverConn := &tlsConn{
		conn:          conn,
		readBuffer:    []byte{},
		versionBuffer: []byte{},
	}

	if err := serverConn.WriteMessage(pendingMessage); err != nil {
		logger.Infof("write pending message to %s failed in RunConnection", serverConn.conn.RemoteAddr())
		return err
	}
	go serverConn.copyConn(clientConn)
	return clientConn.copyConn(serverConn)
}

func (f *ForwardRules) Load() error {
	fn := GetFileLocation(viper.GetString("client.rules"))
	if fn != "" {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			return err
		}
		return f.PutJson(data)
	}
	return nil
}

func (f *ForwardRules) Save() error {
	fn := GetFileLocation(viper.GetString("client.rules"))
	if fn != "" {
		return ioutil.WriteFile(fn, f.GetJson(), 0655)
	}
	return nil
}
