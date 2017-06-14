/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package selinux

import ()
import (
	"github.com/kreon/libselinux"
	"errors"
)

func SetEnforce() error {
	if libselinux.Security_setenforce(1) == 0 {
		return nil
	} else {
		return errors.New("Setenforce(1) failed")
	}
}

func SetPermissive() error {
	if libselinux.Security_setenforce(0) == 0 {
		return nil
	} else {
		return errors.New("Setenforce(0) failed")
	}

}