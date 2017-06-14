/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package api

import (
	"net/http"
	"github.com/julienschmidt/httprouter"
)

func InitRouter() http.Handler {
	r := httprouter.New()
	r.GET("/info", getinfo)
	r.GET("/booleans", getbooleans)
	r.PUT("/enable/:name", enableboolean)
	r.PUT("/disable/:name", disableboolean)
	r.PUT("/setenforce/0", setpermissive)
	r.PUT("/setenforce/1", setenforce)
	r.POST("/restorecon/*path", restorecon)
	return r
}
