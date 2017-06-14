/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package selinux

import (
	"github.com/kreon/libselinux"
)

const (
	PERMISSIVE = "permissive"
	ENFORCING  = "enforcing"
	DISABLED   = "disabled"
)

type SELinuxInfo struct {
	SELinuxMode   string
	SELinuxType   string
	PolicyVersion int
}

func New() *SELinuxInfo {
	enforcing := libselinux.Security_getenforce()
	stype := [][]byte{make([]byte, 100)}
	polver := libselinux.Security_policyvers()
	ret := new(SELinuxInfo)
	libselinux.Selinux_getpolicytype(stype)
	ret.PolicyVersion = int(polver)
	ret.SELinuxType = bb2string(stype)
	switch enforcing {
	case -1:
		ret.SELinuxMode = DISABLED
		break
	case 0:
		ret.SELinuxMode = PERMISSIVE
		break
	case 1:
		ret.SELinuxMode = ENFORCING
		break
	}
	return ret
}
