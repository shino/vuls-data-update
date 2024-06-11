package goodver

import (
	"regexp"
	"strconv"
	"strings"
)

type Goodver struct {
	V     string
	Elems []int
}

var goodRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

func Parse(v string) (bool, Goodver) {
	if !goodRe.MatchString(v) {
		return false, Goodver{}
	}

	tokens := strings.Split(v, ".")
	var elems = make([]int, 0, len(tokens))
	for _, t := range tokens {
		i, _ := strconv.Atoi(t)
		elems = append(elems, i)
	}
	return true, Goodver{V: v, Elems: elems}
}

func Compare(x, y Goodver) int {
	commonLen := min(len(x.Elems), len(y.Elems))
	for i := range commonLen {
		if x.Elems[i] < y.Elems[i] {
			return -1
		}
		if x.Elems[i] > y.Elems[i] {
			return 1
		}
	}
	return len(x.Elems) - len(y.Elems)
}
