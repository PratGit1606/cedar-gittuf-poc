package oracle

import (
	"log/slog"
	"os"
)

func init() {
	// ORACLE_DEBUG=1 surfaces gittuf's own slog.Debug trace (threshold counting etc.).
	if os.Getenv("ORACLE_DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
}
