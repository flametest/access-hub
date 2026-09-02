package service

import (
	"context"
	"time"

	log "github.com/flametest/vita/vlog"

	"github.com/flametest/access-hub/internal/container"
)

// auditRetentionInterval is how often the janitor sweeps. A day is plenty:
// the retention window is measured in months (design.md §10).
const auditRetentionInterval = 24 * time.Hour

// RunAuditRetention deletes audit-log rows older than the configured
// retention window (cfg.Audit.RetentionDays, default 180). It sweeps once at
// startup and then daily; the context cancel (shutdown) stops it. Failures
// are logged and retried on the next sweep — retention must never take the
// service down.
func RunAuditRetention(ctx context.Context, c container.Container) {
	days := c.Cfg().Audit.RetentionDays
	sweep := func() {
		cutoff := time.Now().AddDate(0, 0, -days)
		deleted, err := c.AuditLogRepo().PurgeBefore(ctx, cutoff)
		if err != nil {
			log.Warn().Any("error", err).Any("days", days).Msg("audit retention sweep failed")
			return
		}
		if deleted > 0 {
			log.Info().Any("deleted", deleted).Any("retention_days", days).Msg("audit retention sweep")
		}
	}
	sweep()
	ticker := time.NewTicker(auditRetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}
