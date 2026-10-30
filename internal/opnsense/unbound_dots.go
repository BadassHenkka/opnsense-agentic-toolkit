package opnsense

// Query forwarding servers (Forwards) and DNS over TLS servers (DoTs) share one array,
// dots.dot, told apart by its type field. searchForward and searchDot list one type each,
// but getForward and getDot return an item of either type, and setForward and setDot
// rewrite the type. Get refuses an item of the other type, so that a wrong ID can't turn a
// DNS over TLS server into plain DNS forwarding.

func (*UnboundForward) kind() string { return "forward" }

func (*UnboundDoT) kind() string { return "dot" }
