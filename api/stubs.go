package api

import (
	"net/http"
	"github.com/julienschmidt/httprouter"
	"encoding/json"
	"../selinux"
	"errors"
)

type selinux_info struct {
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Version int `json:"version"`
}

type boolean struct {
	Name    string `json:"name"`
	Enabled bool `json:"enabled"`
}

type boolean_info struct {
	Booleans []boolean `json:"booleans"`
}

type status struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func genstatus(e error) status {
	if e != nil {
		return status{
			Status:"error",
			Error:e.Error(),
		}
	} else {
		return status{
			Status:"ok",
		}
	}
}

func getinfo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// available for all
	info := selinux.New()
	json.NewEncoder(w).Encode(selinux_info{
		Mode:info.SELinuxMode,
		Type:info.SELinuxType,
		Version:info.PolicyVersion,
	})
}

func getbooleans(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	ret := boolean_info{
		Booleans:[]boolean{},
	}
	for _, bool := range selinux.GetBooleans() {
		ret.Booleans = append(ret.Booleans, boolean{
			Name:bool.Name,
			Enabled:bool.Value,
		})
	}
	json.NewEncoder(w).Encode(ret)
}

func enableboolean(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	e := (&selinux.SELinuxBoolean{Name:ps.ByName("name")}).Enable()
	json.NewEncoder(w).Encode(genstatus(e))
}

func disableboolean(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	e := (&selinux.SELinuxBoolean{Name:ps.ByName("name")}).Disable()
	json.NewEncoder(w).Encode(genstatus(e))
}

func setenforce(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	e := selinux.SetEnforce()
	json.NewEncoder(w).Encode(genstatus(e))
}

func setpermissive(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	e := selinux.SetPermissive()
	json.NewEncoder(w).Encode(genstatus(e))
}

func restorecon(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !is_verified(r) {
		w.WriteHeader(403)
		return
	}
	recursive := false
	rr := r.URL.Query().Get("recursive")
	if rr != "" {
		if rr == "true" || rr == "1" {
			recursive = true
		}
	}
	path := ps.ByName("path")
	if len(path) == 0 {
		json.NewEncoder(w).Encode(genstatus(errors.New("Empty path, use // for root instead")))
	} else {
		selinux.RestoreCon(path, recursive)
		json.NewEncoder(w).Encode(genstatus(nil))
	}

}



