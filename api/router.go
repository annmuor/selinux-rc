/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package api

import (
	"../plugins"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

type MyOwnRouter struct {
	router http.Handler
}

func (h *MyOwnRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if plugins.RequestIntercept(w, r) {
		return
	} else {
		h.router.ServeHTTP(w, r)
	}

}

func InitRouter() http.Handler {
	r := httprouter.New()
	r.GET("/info", getinfo)
	r.GET("/booleans", getbooleans)
	r.PUT("/enable/:name", enableboolean)
	r.PUT("/disable/:name", disableboolean)
	r.PUT("/setenforce/0", setpermissive)
	r.PUT("/setenforce/1", setenforce)
	r.POST("/restorecon/*path", restorecon)
	or := new(MyOwnRouter)
	or.router = r
	return or
}
