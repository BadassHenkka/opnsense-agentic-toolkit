package opnsensetest

// registerAll declares every API area the fake serves. Add new areas here.
func registerAll(s *Server) {
	registerGenerated(s) // zz_gen_*.go; the functions below add hand-written behaviour
}
