package logging

import (
	".."
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	MAIL_ADDRESS = "logging_mail_address"
	FILTER       = "logging_filter"
	FORMAT       = "logging_format"
	LOGFILE      = "logging_logfile"
)

type Plugin struct {
	filter string
	format string
	logger *log.Logger
	mailer *mailer
}

func Init(config map[string]string) plugins.Plugin {
	if config[MAIL_ADDRESS] == "" && config[LOGFILE] == "" {
		panic("Failed to init logging plugin: you must set either mail_address or logfile")
	}
	p := new(Plugin)
	if config[LOGFILE] != "" {
		if s, e := os.OpenFile(config[LOGFILE], os.O_APPEND|os.O_CREATE, 0644); e == nil {
			p.logger = log.New(s, "selinux-rc", log.LstdFlags|log.LUTC)
		} else {
			panic(fmt.Sprintf("Failed to open logfile: %s", e.Error()))
		}
	}
	if config[MAIL_ADDRESS] != "" {
		p.mailer = newMailer("localhost", 25, "root", config[MAIL_ADDRESS])
	}
	if config[FILTER] != "" {
		p.filter = config[FILTER]
	} else {
		p.filter = "^(POST|PUT)"
	}
	if config[FORMAT] != "" {
		p.format = config[FORMAT]
	} else {
		p.format = "{METHOD} {IP} {USERNAME} {CERTIFICATE} {URL}"
	}
	return p
}

func (l *Plugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	return false
}

type mailer struct {
	server string
	port   int
	from   string
	to     string
}

func newMailer(server string, port int, from, to string) *mailer {
	m := &mailer{
		server: server,
		port:   port,
		from:   from,
		to:     to,
	}
	return m
}

func (m *mailer) log(r *http.Request) {

}
