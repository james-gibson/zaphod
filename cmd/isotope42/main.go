// Command isotope42 reads a preloaded isotope set in the library's own terms.
//
// The 42i arithmetic is not reimplemented here: the weights, the rung thresholds
// and the position are the isotope library's (fortytwointegration.go). This
// command exists so the fixture's claims are checked by the same code a real
// cluster uses, and so the red team can say what a change would cost on the axis.
//
//	isotope42 check isotopes/zaphod-base.json
//	isotope42 drift --accepted 1 [--family scope-compliance]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/james-gibson/isotope"
)

type position struct {
	Real      float64 `json:"real"`
	Imaginary float64 `json:"imaginary"`
	Rung      int     `json:"rung"`
}

type preloaded struct {
	Version  int    `json:"version"`
	Cluster  string `json:"cluster"`
	IssuedBy string `json:"issued_by"`
	Expires  string `json:"expires"`
	Isotopes []struct {
		ID       string   `json:"id"`
		Role     string   `json:"role"`
		Endpoint string   `json:"endpoint"`
		Position position `json:"position"`
		Hops     int      `json:"hops"`
		Skills   []string `json:"skills"`
	} `json:"isotopes"`
}

func usage() {
	fmt.Fprint(os.Stderr, `isotope42 — read a preloaded isotope set in 42i terms

  isotope42 check <file>                 validate each position against its rung
  isotope42 drift --accepted N [--family F]
                                         the cluster's position after N accepted
                                         violations (default scope-compliance)
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "check":
		if len(os.Args) < 3 {
			usage()
		}
		os.Exit(check(os.Args[2]))
	case "drift":
		os.Exit(drift(os.Args[2:]))
	default:
		usage()
	}
}

// check refuses a set whose position and rung disagree: a rung is a claim about
// accumulated distance, and the library already knows the mapping, so there is no
// reason to take the pair on trust.
func check(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "isotope42: %v\n", err)
		return 1
	}
	var set preloaded
	if err := json.Unmarshal(data, &set); err != nil {
		fmt.Fprintf(os.Stderr, "isotope42: parse %s: %v\n", path, err)
		return 1
	}
	if set.Version != 1 {
		fmt.Fprintf(os.Stderr, "isotope42: unsupported version %d\n", set.Version)
		return 1
	}

	bad := 0
	for _, iso := range set.Isotopes {
		if iso.ID == "" || !strings.HasPrefix(iso.ID, set.Cluster+"/") {
			fmt.Fprintf(os.Stderr, "isotope42: %s: id is not under %q\n", iso.ID, set.Cluster)
			bad++
			continue
		}
		if iso.Position.Real != 42 {
			fmt.Fprintf(os.Stderr, "isotope42: %s: real axis is %.1f, every position is at 42\n", iso.ID, iso.Position.Real)
			bad++
		}
		distance := int(iso.Position.Imaginary)
		if min := iso.Hops * isotope.DefaultWeights["isotope-variation"]; distance < min {
			fmt.Fprintf(os.Stderr, "isotope42: %s: %d proxy hop(s) carry at least distance %d, position says %d\n",
				iso.ID, iso.Hops, min, distance)
			bad++
			continue
		}
		rung := isotope.RungForDistance(distance, isotope.DefaultRungThresholds)
		if rung != iso.Position.Rung {
			fmt.Fprintf(os.Stderr, "isotope42: %s: rung %d claimed at distance %d, which is rung %d\n",
				iso.ID, iso.Position.Rung, distance, rung)
			bad++
			continue
		}
		fmt.Printf("  %-40s 42 + %.0fi (rung %d)  %d hop(s)  (%d skill(s))\n",
			iso.ID, iso.Position.Imaginary, iso.Position.Rung, iso.Hops, len(iso.Skills))
	}
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "isotope42: %d position(s) inconsistent\n", bad)
		return 1
	}
	// The rung is a function of the distance, recomputed here from the evidence. That
	// is the point of the design: a cluster that voted on rungs would race, and two
	// observers would disagree while both were right about what they saw. A pure
	// function cannot disagree with itself.
	fmt.Printf("positions ok: %d isotope(s) in %s — rung is a function of distance, not a vote\n",
		len(set.Isotopes), set.Cluster)
	return 0
}

// drift answers the question the red team asks: if this attempt had been accepted,
// where would the cluster be? Distance comes from the library's own weights.
func drift(args []string) int {
	accepted := 0
	family := "scope-compliance"
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--accepted" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &accepted)
			i++
		case args[i] == "--family" && i+1 < len(args):
			family = args[i+1]
			i++
		default:
			usage()
		}
	}
	if _, ok := isotope.DefaultWeights[family]; !ok {
		fmt.Fprintf(os.Stderr, "isotope42: unknown family %q\n", family)
		return 2
	}

	state := isotope.NewAgentState("zaphod-base")
	for i := 0; i < accepted; i++ {
		state.RecordTestFailure(family)
	}
	fmt.Printf("42i %s\n", state.Position.String())
	if accepted > 0 {
		fmt.Printf("verdict: drifted — %d accepted violation(s) of %s; distance %d from ground truth (direction: %s)\n",
			accepted, family, state.TotalDistance, state.Position.Direction)
		return 0
	}
	fmt.Printf("verdict: ground truth — nothing was accepted\n")
	return 0
}
