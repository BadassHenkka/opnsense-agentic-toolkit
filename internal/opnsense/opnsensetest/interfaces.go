package opnsensetest

import "fmt"

// registerAssignments makes interface assignments behave like OPNsense: items are keyed by
// identifier, new ones get the next free optN, and lan and wan exist from the start.
func registerAssignments(s *Server) {
	c := s.collection("interfaces/assignment", "interface")
	c.NewID = func(_ *Server, rec Record) string {
		for n := 1; ; n++ {
			id := fmt.Sprintf("opt%d", n)
			if _, used := c.items[id]; !used {
				rec["identifier"] = id
				return id
			}
		}
	}
	for id, dev := range map[string]string{"lan": "vtnet0", "wan": "vtnet1"} {
		rec := c.Defaults()
		rec["identifier"], rec["if"], rec["descr"], rec["enable"] = id, dev, map[string]string{"lan": "LAN", "wan": "WAN"}[id], "1"
		c.items[id] = rec
	}
}
