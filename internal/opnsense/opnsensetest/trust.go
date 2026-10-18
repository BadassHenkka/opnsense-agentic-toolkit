package opnsensetest

import "fmt"

// registerTrust imitates the action handling of trust/ca and trust/cert: generating actions
// produce a certificate (and keep the private key server-side), import actions store what
// was posted, and reads report the action OPNsense derives from what is stored.
func registerTrust(s *Server) {
	for _, base := range []struct{ path, key string }{{"trust/ca", "ca"}, {"trust/cert", "cert"}} {
		c := s.collection(base.path, base.key)
		prev := c.OnWrite
		c.OnWrite = func(s *Server, uuid string, posted Record) {
			if prev != nil {
				prev(s, uuid, posted)
			}
			s.operations = append(s.operations, base.key+":"+posted["action"])
			switch posted["action"] {
			case "internal", "ocsp", "reissue":
				s.nextID++
				posted["crt_payload"] = fmt.Sprintf("-----BEGIN CERTIFICATE-----\nfake %s %d\n-----END CERTIFICATE-----\n", posted["commonname"], s.nextID)
				posted["prv_payload"] = "-----BEGIN PRIVATE KEY-----\nserver side\n-----END PRIVATE KEY-----\n"
				posted["valid_from"], posted["valid_to"] = "1760000000", "1830000000"
			case "external":
				posted["csr_payload"] = "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n"
				posted["prv_payload"] = "-----BEGIN PRIVATE KEY-----\nserver side\n-----END PRIVATE KEY-----\n"
			}
			if old, ok := c.items[uuid]; ok && posted["prv_payload"] == "" {
				posted["prv_payload"] = old["prv_payload"] // an empty key keeps the stored one
			}
			// Volatile parameters are not stored: reads return the model defaults again.
			posted["action"] = "manual"
			if posted["prv_payload"] != "" {
				posted["action"] = map[string]string{"ca": "internal", "cert": "reissue"}[base.key]
			}
			for _, f := range []string{"key_type", "digest", "lifetime"} {
				posted[f] = c.Fields[f].Default
			}
		}
	}
}
