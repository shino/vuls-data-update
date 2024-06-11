package goodver_test

import (
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/cmd/vulnrichment/goodver"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		x    string
		y    string
		want int
	}{
		{
			x:    "1.2.3",
			y:    "1.2.3",
			want: 0,
		},
		{
			x:    "1.2.3",
			y:    "1.3.3",
			want: -1,
		},
		{
			x:    "2.2.3",
			y:    "0.2.3",
			want: 1,
		},
		{
			x:    "1.2",
			y:    "1.2.0",
			want: -1,
		},
		{
			x:    "0",
			y:    "126.0.6478.54",
			want: -1,
		},
		{
			x:    "17.7",
			y:    "17.12",
			want: -1,
		},
		{
			x:    "17.12",
			y:    "17.7",
			want: +1,
		},
		{
			x:    "8.1",
			y:    "8.1.13",
			want: -1,
		},
		{
			x:    "8.1.99",
			y:    "8.1",
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.x, tt.y}, " vs "), func(t *testing.T) {
			_, l := goodver.Parse(tt.x)
			_, r := goodver.Parse(tt.y)

			if goodver.Compare(l, r) != tt.want {
				t.Errorf("Compare(%s, %s) = %d; want %d", tt.x, tt.y, goodver.Compare(l, r), tt.want)
			}
		})
	}
}
