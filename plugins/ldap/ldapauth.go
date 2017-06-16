package ldap

import (
	"net/http"
	"strconv"
	"gopkg.in/ldap.v2"
	"fmt"
	"crypto/tls"
	"log"
	"strings"
)

const (
	BASE   = "ldap_base"
	HOST   = "ldap_host"
	PORT   = "ldap_port"
	SSL    = "ldap_use_ssl"
	DOMAIN = "ldap_domain"
)

type LdapPlugin struct {
	base   string
	host   string
	domain string
	port   int
	ssl    bool
}

func (l *LdapPlugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if ok {
		if l.domain != "" {
			_d := fmt.Sprintf("%s\\", l.domain)
			if !strings.HasPrefix(_d, username) {
				username = fmt.Sprintf("%s%s", _d, username)
			}
		}
		ok = false
		var conn *ldap.Conn
		var e error
		address := fmt.Sprintf("%s:%d", l.host, l.port)
		if l.ssl {
			config := &tls.Config{
				InsecureSkipVerify: true,
			}
			conn, e = ldap.DialTLS("tcp", address, config)
		} else {
			conn, e = ldap.Dial("tcp", address)
		}
		if e == nil {
			defer conn.Close()
			if conn.Bind(username, password) == nil {
				ok = true
			} else {
				log.Println("Auth failed for", username)
			}
		} else {
			log.Println("Something went wrong with ldap:", e.Error())
		}
	}
	if !ok {
		if !ok {
			w.Header().Add("WWW-Authenticate", `Basic realm="ActiveDirectory auth"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return true
		}
	}
	return false
}

func Init(config map[string]string) *LdapPlugin {
	l := new(LdapPlugin)
	port, _ := strconv.Atoi(config[PORT])
	ssl := true
	if config[SSL] == "false" {
		ssl = false
	}
	l.base = config[BASE]
	l.port = port
	l.host = config[HOST]
	l.ssl = ssl
	l.domain = config[DOMAIN]
	return l
}
