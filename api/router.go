package api

import (
	"github.com/julienschmidt/httprouter"
	"net/http"
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
