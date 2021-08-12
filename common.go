package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	logger                *zap.SugaredLogger
	errInvaildClientHello = errors.New("invalid TLS ClientHello data")
	errInvalidTLSPacket   = errors.New("invalid TLS packet data")
	errInvalidTLSProtocol = errors.New("invalid TLS protocol")
	errTargetRejected     = errors.New("target host rejected")
)
var (
	configName = flag.String("config", "rproxy.yaml", "")
)

func setupLog() {
	logpath := viper.GetString("global.logfile")
	errpath := viper.GetString("global.errfile")
	config := zap.NewProductionConfig()
	if logpath != "" {
		config.OutputPaths = []string{
			logpath,
		}
	}
	if errpath != "" {
		config.ErrorOutputPaths = []string{
			errpath,
		}
	}
	logbase, _ := config.Build()
	logger = logbase.Sugar()
}

func setupDefaults() {
	viper.SetDefault("global.root", filepath.Dir(os.Args[0]))
	viper.SetDefault("https.listen", ":443")
	viper.SetDefault("http.listen", ":80")
	viper.SetDefault("console.listen", ":2080")
}
func setupConfig() {
	flag.Parse()
	viper.SetConfigName(*configName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath(filepath.Dir(os.Args[0]))
	setupDefaults()
	var err error
	if err = viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			panic(fmt.Errorf("config file not found: %s", err))
		} else {
			panic(fmt.Errorf("fatal error config file: %s", err))
		}
	}
}

func startDefaultHTTPServer() {
	go func() {
		err := http.ListenAndServe(viper.GetString("console.listen"), nil)
		if err != nil {
			logger.Panicf("Unable to listen to %s, err %v", viper.GetString("console.listen"), err)
		}
	}()
}

func GetFileLocation(fn string) string {
	if filepath.IsAbs(fn) {
		return fn
	}
	root := viper.GetString("global.root")
	if root != "" {
		return filepath.Join(root, fn)
	}
	return fn
}

func LogAccess(protocol, from, to string) {
	logger.Infow("access", "scheme", protocol, "from", from, "to", to)
}
