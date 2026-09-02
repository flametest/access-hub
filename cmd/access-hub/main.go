package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"
	"time"

	"github.com/flametest/access-hub/internal/api"
	"github.com/flametest/access-hub/internal/bootstrap"
	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/access-hub/internal/container"
	"github.com/flametest/access-hub/internal/service"
	"github.com/flametest/vita/verrors"
	"github.com/flametest/vita/vlog"
	"github.com/flametest/vita/vserver"
)

var cfgFile = flag.String("config", "deploy/server-config.yaml", "config file")

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)
	defer stop()

	cfg, err := config.ParseConfig(*cfgFile)
	if err != nil {
		panic(err)
	}
	verrors.Initialize(cfg.AppConfig.Name)
	log.InitLogger(log.ZerologType, cfg.AppConfig.Name, cfg.LogLevel)
	log.Info().Msg("starting access-hub")

	c, err := container.NewContainer(cfg)
	if err != nil {
		panic(err)
	}

	// Readiness gate: "ready" only when BOTH the database and Redis are
	// reachable — the denylist, rate limits, policy epoch and watcher all
	// depend on Redis, so a Redis outage must pull the instance out of the
	// load-balancer pool (the denylist fails closed by default).
	ready := func(ctx context.Context) error {
		sqlDB, err := c.DB().DB()
		if err != nil {
			return err
		}
		if err := sqlDB.PingContext(ctx); err != nil {
			return err
		}
		return c.Redis().Redis().Ping(ctx).Err()
	}
	srv, err := vserver.NewEchoServer(ctx, &cfg.AppConfig, vserver.WithMetrics(), vserver.WithReadinessCheck(ready))
	if err != nil {
		panic(err)
	}
	app := api.NewApp(c)
	srv.Register(app.Router)

	// Idempotent bootstrap (admin app, built-in roles, platform admin)
	// before the listener starts accepting traffic.
	if err := bootstrap.Run(ctx, c); err != nil {
		log.Error().Any("error", err).Msg("bootstrap failed")
		c.Close()
		panic(err)
	}

	// Idempotent admin dogfood resource sync (constant table -> admin app
	// resources + org_admin binding + enforcer reload). Fatal on failure,
	// same as bootstrap: a console with an unsynced permission surface must
	// not come up half-configured.
	if err := api.SyncAdminResources(ctx, c); err != nil {
		log.Error().Any("error", err).Msg("admin resource sync failed")
		c.Close()
		panic(err)
	}

	// Audit-log retention janitor (design §10: configurable, default 180d).
	go service.RunAuditRetention(ctx, c)

	go func() {
		_ = srv.Start(ctx)
	}()

	<-ctx.Done()

	log.Info().Msg("shutting down gracefully...")

	// Drain HTTP first, then release the watcher, Redis and DB connections
	// so in-flight requests keep their dependencies.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal().Any("error", err).Msg("Server forced to shutdown")
	}

	c.Close()
	log.Info().Msg("Server exiting")
}
