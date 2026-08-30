package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flametest/access-hub/internal/config"
	"github.com/flametest/vita/vgorm"
	log "github.com/flametest/vita/vlog"
)

// migrate applies migration/*.sql in lexical order, tracking applied files
// in schema_migrations. Statement splitting is line-comment aware (no stored
// procedures in our SQL, so a naive ";" split after comment stripping is safe).
func main() {
	configPath := flag.String("config", "deploy/server-config.yaml", "path to config file")
	dir := flag.String("dir", "migration", "directory containing .sql files")
	flag.Parse()

	log.InitLogger(log.ZerologType, "access-hub-migrate", 0)

	cfg, err := config.ParseConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(1)
	}
	db, err := vgorm.NewDB(cfg.Datasource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect db: %v\n", err)
		os.Exit(1)
	}

	if err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		filename   VARCHAR(255) PRIMARY KEY,
		applied_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`).Error; err != nil {
		fmt.Fprintf(os.Stderr, "ensure schema_migrations: %v\n", err)
		os.Exit(1)
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*.sql"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob migrations: %v\n", err)
		os.Exit(1)
	}
	sort.Strings(files)

	for _, f := range files {
		name := filepath.Base(f)
		var count int64
		if err := db.Table("schema_migrations").Where("filename = ?", name).Count(&count).Error; err != nil {
			fmt.Fprintf(os.Stderr, "check applied: %v\n", err)
			os.Exit(1)
		}
		if count > 0 {
			log.Info().Any("file", name).Msg("skip applied migration")
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", f, err)
			os.Exit(1)
		}
		for i, stmt := range splitSQL(string(data)) {
			if err := db.Exec(stmt).Error; err != nil {
				fmt.Fprintf(os.Stderr, "apply %s stmt#%d: %v\n", name, i+1, err)
				os.Exit(1)
			}
		}
		if err := db.Exec("INSERT INTO schema_migrations (filename) VALUES (?)", name).Error; err != nil {
			fmt.Fprintf(os.Stderr, "record %s: %v\n", name, err)
			os.Exit(1)
		}
		log.Info().Any("file", name).Msg("applied migration")
	}
	log.Info().Msg("migrations up to date")
}

// splitSQL strips line comments (cutting each line at "--") and splits the
// remainder on semicolons, dropping whitespace-only statements.
func splitSQL(data string) []string {
	var b strings.Builder
	for _, line := range strings.Split(data, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	var out []string
	for _, stmt := range strings.Split(b.String(), ";") {
		if trimmed := strings.TrimSpace(stmt); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
