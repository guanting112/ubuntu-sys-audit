// Package dpkg reads the dpkg database without invoking any binary from the
// host, and implements Debian version ordering.
package dpkg

import (
	"strconv"
	"strings"
)

// Compare orders two Debian version strings per deb-version(7). It returns a
// negative value when a < b, zero when equal and positive when a > b.
func Compare(a, b string) int {
	ae, au, ar := split(a)
	be, bu, br := split(b)
	if ae != be {
		if ae < be {
			return -1
		}
		return 1
	}
	if c := compareFragment(au, bu); c != 0 {
		return c
	}
	return compareFragment(ar, br)
}

func split(v string) (epoch int64, upstream, revision string) {
	// dpkg keeps versions as C strings, which end at a NUL byte. Past one,
	// compareFragment could not tell the byte from the end of the string.
	if i := strings.IndexByte(v, 0); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.ParseInt(v[:i], 10, 64); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// order ranks a non-digit character: '~' sorts before everything, including
// the end of the string; letters sort before other characters.
func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case c == 0:
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	}
	return int(c) + 256
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func compareFragment(a, b string) int {
	i, j := 0, 0
	at := func(s string, n int) byte {
		if n < len(s) {
			return s[n]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			oa, ob := order(at(a, i)), order(at(b, j))
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		diff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if diff != 0 {
			if diff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}
