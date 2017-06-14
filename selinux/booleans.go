/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package selinux

import (
	"github.com/kreon/libselinux"
	"errors"
)

type SELinuxBoolean struct {
	Name  string
	Value bool
}

func GetBooleans() []*SELinuxBoolean {
	names := get_boolean_names(1024)
	ret := make([]*SELinuxBoolean, len(names))
	for i, name := range names {
		ret[i] = new(SELinuxBoolean)
		ret[i].Name = name
		ret[i].Value = get_boolean_value(name)
	}
	return ret
}

func (b *SELinuxBoolean) Enable() error {
	bb := []libselinux.SELboolean{libselinux.SELboolean{Name:[]byte(b.Name), Value:1}}
	if libselinux.Security_set_boolean_list(1, bb, 0) == 0 {
		return nil
	} else {
		return errors.New("Setting boolean failed")
	}
}

func (b *SELinuxBoolean) Disable() error {
	bb := []libselinux.SELboolean{libselinux.SELboolean{Name:[]byte(b.Name), Value:0}}
	if libselinux.Security_set_boolean_list(1, bb, 0) == 0 {
		return nil
	} else {
		return errors.New("Setting boolean failed")
	}
}

func get_boolean_names(max int) []string {
	l := []int32{int32(max) };
	n := [][][]byte{make([][]byte, max) }
	for i := range n[0] {
		n[0][i] = make([]byte, 255)
	}
	if libselinux.Security_get_boolean_names(n, l) == -1 {
		return []string{}
	}
	ret := make([]string, int(l[0]))
	for v := 0; v < int(l[0]); v++ {
		ret[v] = b2string(n[0][v])
	}
	return ret
}

func get_boolean_value(name string) bool {
	val1 := libselinux.Security_get_boolean_active(name)
	val2 := libselinux.Security_get_boolean_pending(name)
	if val1 == val2 {
		return val1 == 1
	} else {
		return val2 == 1
	}
}