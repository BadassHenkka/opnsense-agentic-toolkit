package opnsense

import (
	"context"
	"fmt"
	"time"
)

// ApplyAssignments reconfigures the interfaces and then checks that the API still answers
// over a new connection: a wrong address or device on the interface the client talks
// through cuts it off.
func (s *InterfacesService) ApplyAssignments(ctx context.Context) error {
	if err := s.Assignments.Apply(ctx); err != nil {
		return err
	}
	if err := s.c.VerifyReachable(ctx, 15*time.Second); err != nil {
		return fmt.Errorf("opnsense: interfaces applied, but %w; check the interface this client connects through", err)
	}
	return nil
}
