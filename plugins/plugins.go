package plugins

import (
	"./basic"
	"./ldap"
	"./logging"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

const (
	ENABLED = "plugins_enabled"
)

var currentConfig map[string]string

var loadedPlugins map[string]SELinuxPlugin

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

func RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	if loadedPlugins == nil {
		loadedPlugins = make(map[string]SELinuxPlugin)
		enabled := strings.Split(currentConfig[ENABLED], ",")
		defer func() {
			if e := recover(); e != nil {
				log.Fatal(e)
			}
		}() // init can panic if something went wrong
		if sort.SearchStrings(enabled, "ldap") {
			if loadedPlugins["ldap"] == nil {
				loadedPlugins["ldap"] = ldap.Init(currentConfig)
			}
		}
		if sort.SearchStrings(enabled, "basic") {
			if loadedPlugins["basic"] == nil {
				loadedPlugins["basic"] = basic.Init(currentConfig)
			}
		}
		if sort.SearchStrings(enabled, "logging") {
			if loadedPlugins["logging"] == nil {
				loadedPlugins["logging"] = logging.Init(currentConfig)
			}
		}
	}
	intercept := false
	for _, v := range loadedPlugins {
		if v.RequestIntercept(w, r) {
			intercept = true
		}
	}
	return intercept
}
