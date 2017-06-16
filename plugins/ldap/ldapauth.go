package ldap

import (
	"github.com/jtblin/go-ldap-client"
	"net/http"
)

type LdapPlugin struct {
	config map[string]string
	client ldap.LDAPClient
}

func (l *LdapPlugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	return false
}

func Init(config map[string]string) *LdapPlugin {
	return nil
}
