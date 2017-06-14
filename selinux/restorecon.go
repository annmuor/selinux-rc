/**
 * SELINUX-RC project
 * (C) Ivan Agarkov, 2017
 */
package selinux

import (
	"github.com/kreon/libselinux"
	"io/ioutil"
	"path/filepath"
)

func RestoreCon(path string, recursive bool) {
	x := make(chan string)
	go goproc(x)

	if recursive {
		q := []string{path}
		q1 := []string{}
		start:
		for _, p := range q {
			ls, e := ioutil.ReadDir(p)
			if e != nil {
				x <- path
				continue
			}
			for _, c := range ls {
				rl := filepath.Join(p, c.Name())
				x <- rl
				if c.IsDir() {
					q1 = append(q1, rl)
				}
			}
		}
		if len(q1) > 0 {
			q = q1
			q1 = []string{}
			goto start
		}
	} else {
		x <- path
	}
	close(x)
}

func getfilecon(path string) string {
	mycon := [][]byte{make([]byte, 100)}
	libselinux.Getfilecon(path, mycon)
	ret := bb2string(mycon)
	return ret
}

func matchpathcon(path string) string {
	mycon := [][]byte{make([]byte, 100)}
	libselinux.Matchpathcon(path, 0, mycon)
	ret := bb2string(mycon)
	return ret
}

func setfilecon(path, con string) {
	libselinux.Setfilecon(path, con)
}

func restorecon(path string) {
	con1 := getfilecon(path)
	con2 := matchpathcon(path)
	if con1 != con2 {
		setfilecon(path, con2)
	}
}

func goproc(x chan string) {
	for name := range x {
		restorecon(name)
	}
}