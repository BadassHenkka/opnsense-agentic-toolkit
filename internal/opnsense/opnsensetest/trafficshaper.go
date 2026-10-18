package opnsensetest

import "strconv"

// registerTrafficShaper numbers pipes and queues like TrafficShaper::newPipeNumber and
// newQueueNumber: a new item gets the next free number, an edit keeps its own. Rules refer
// to the items by uuid, so the number only matters to the firewall.
func registerTrafficShaper(s *Server) {
	for _, key := range []string{"pipe", "queue"} {
		c := s.collection("trafficshaper/settings", key)
		c.OnWrite = func(_ *Server, uuid string, posted Record) {
			if old, ok := c.items[uuid]; ok {
				posted["number"] = old["number"]
				return
			}
			next := 1
			for _, r := range c.items {
				if n, err := strconv.Atoi(r["number"]); err == nil && n >= next {
					next = n + 1
				}
			}
			posted["number"] = strconv.Itoa(next)
		}
	}
}
