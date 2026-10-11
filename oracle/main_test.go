package oracle

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := CheckGittufDir(); err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
