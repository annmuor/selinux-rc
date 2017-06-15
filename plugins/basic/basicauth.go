package basic

import (
	".."
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const (
	PASSWORD_FILE = "basic_passwordfile"
)

type Plugin struct {
	password_file string
}

/**
password file format
user:password
ok
*/
func (l *Plugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if ok { // check if ok
		ok = false
		if l, e := ioutil.ReadFile(l.password_file); e == nil {
			for _, s := range strings.Split(string(l), "\n") {
				if s == fmt.Sprintf("%s:%s", username, password) {
					ok = true
					break
				}
			}

		}
	}
	if !ok {
		w.Header().Add("WWW-Authenticate", `Basic realm="selinux-tools"`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return true
	}
	return false
}

func Init(config map[string]string) plugins.Plugin {
	if config[PASSWORD_FILE] != "" {
		if f, e := os.Open(config[PASSWORD_FILE]); e == nil {
			f.Close()
		} else {
			panic("Can't load basic plugin! basic_passwordfile is invalid")
		}
	}
	p := new(Plugin)
	p.password_file = config[PASSWORD_FILE]
	return p
}
