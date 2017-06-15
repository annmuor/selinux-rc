package ldap

import (
	".."
	"github.com/jtblin/go-ldap-client"
	"net/http"
)

type Plugin struct {
	config map[string]string
	client ldap.LDAPClient
}

func (l *Plugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	return false
}

func Init(config map[string]string) plugins.Plugin {
	return nil
}
