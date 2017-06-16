package logging

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"regexp"
	"net/smtp"
	"time"
)

const (
	MAIL_ADDRESS = "logging_mail_address"
	FILTER       = "logging_filter"
	FORMAT       = "logging_format"
	LOGFILE      = "logging_logfile"
	TEMPLATE     = `From: %s
To: %s
Date: %s
Subject: SELinux was altered at %s

%s
--
selinux-rc maillogging plugin
`
)

type MailPlugin struct {
	filter string
	format string
	logger *log.Logger
	mailer *mailer
}

func Init(config map[string]string) *MailPlugin {
	if config[MAIL_ADDRESS] == "" && config[LOGFILE] == "" {
		panic("Failed to init logging plugin: you must set either mail_address or logfile")
	}
	p := new(MailPlugin)
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

func (l *MailPlugin) messageFormatAndFilter(r *http.Request) (string, bool) {
	get_username := func() string {
		u, _, o := r.BasicAuth();
		if o {
			return u
		} else {
			return "-"
		}
	}
	get_cert := func() string {
		cs := r.TLS.PeerCertificates
		for _, c := range cs {
			return c.SerialNumber.Text(16)
		}
		return "-"
	}
	message := l.format
	message = strings.Replace(message, "{METHOD}", "", -1)
	message = strings.Replace(message, "{IP}", r.RemoteAddr, -1)
	message = strings.Replace(message, "{USERNAME}", get_username(), -1)
	message = strings.Replace(message, "{CERTIFICATE}", get_cert(), -1)
	message = strings.Replace(message, "{URL}", r.RequestURI, -1)
	o, _ := regexp.MatchString(l.filter, message)
	return message, o
}
func (l *MailPlugin) RequestIntercept(w http.ResponseWriter, r *http.Request) bool {
	if m, o := l.messageFormatAndFilter(r); o {
		if l.mailer != nil {
			go l.mailer.log(m)
		}
		if l.logger != nil {
			l.logger.Println(m)
		}
	}
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

func (m *mailer) log(message string) {
	h, _ := os.Hostname()
	msg := fmt.Sprintf(TEMPLATE, m.from, m.to, time.Now().String(), h, message)
	if e := smtp.SendMail(fmt.Sprintf("%s:%d", m.server, m.port), nil, m.from,
		[]string{m.to}, []byte(msg)); e != nil {
		log.Printf("Error while sending mail to %s:%d: %s", m.server, m.port, e.Error())
	}

}
