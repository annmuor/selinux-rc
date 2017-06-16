package plugins

import (
	"./basic"
	"./ldap"
	"./logging"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	ENABLED = "plugins_enabled"
)

var currentConfig map[string]string

var loadedPlugins []SELinuxPlugin

func loadDefaultConfig() {
	currentConfig[ENABLED] = ""
}

type SELinuxPlugin interface {
	RequestIntercept(w http.ResponseWriter, r *http.Request) bool
}

func LoadConfig(filename string) {
	currentConfig = make(map[string]string)
	loadedPlugins = nil
	defer func() {
		if e := recover(); e != nil {
			log.Println("LoadConfig: Something went wrong", e)
			loadDefaultConfig()
		}
	}()
	if filename == "" {
		loadDefaultConfig()
		return
	} else {
		if f, e := os.Open(filename); e == nil {
			d := json.NewDecoder(f)
			if e := d.Decode(&currentConfig); e != nil {
				panic(e.Error())
			}
		} else {
			panic(e.Error())
		}
	}
}

func has(x []string, y string) bool {
	for _, i := range x {
		if i == y {
			return true
		}
	}
	return false
}

func RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	if loadedPlugins == nil {
		loadedPlugins = make([]SELinuxPlugin, 0)
		enabled := strings.Split(currentConfig[ENABLED], ",")
		defer func() {
			if e := recover(); e != nil {
				log.Fatal(e)
			}
		}() // init can panic if something went wrong
		if has(enabled, "ldap") {
			loadedPlugins = append(loadedPlugins, ldap.Init(currentConfig))
		}
		if has(enabled, "basic") {
			loadedPlugins = append(loadedPlugins, basic.Init(currentConfig))
		}
		if has(enabled, "logging") {
			loadedPlugins = append(loadedPlugins, logging.Init(currentConfig))
		}
	}
	for _, v := range loadedPlugins {
		if v.RequestIntercept(w, r) {
			return true
		}
	}
	return false
}
