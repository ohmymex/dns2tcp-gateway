package banner

import (
	"fmt"
	"io"
	"strings"

	"github.com/ohmymex/dns2tcp-gateway/internal/version"
)

// ANSI color codes.
const (
	cyan      = "\033[96m"
	boldWhite = "\033[1;37m"
	green     = "\033[92m"
	dim       = "\033[2m"
	reset     = "\033[0m"
)

const art = `
    ____  _   _______ ___  __________  ____
   / __ \/ | / / ___/|__ \/_  __/ __ \/ __ \
  / / / /  |/ /\__ \__/ / / / / /  \/ / /_/ /
 / /_/ / /|  /___/ / __/ / / / /__/  / ____/
/_____/_/ |_//____/____//_/  \____/ /_/
`

// Print writes the startup banner to the given writer.
// Accepts multiple domains; all are displayed in the banner line.
func Print(w io.Writer, domains []string, dnsAddr, apiAddr string) {
	fmt.Fprintf(w, "%s%s%s", cyan, art, reset)
	fmt.Fprintf(w, " %sDNS2TCP Gateway%s %s\n", boldWhite, reset, version.String())
	fmt.Fprintf(w, " %sGo %s on %s%s\n", dim, version.GoVersion(), version.Platform(), reset)
	fmt.Fprintf(w, " %sCreated by NumeX (numex.sh)%s\n", dim, reset)
	fmt.Fprintf(w, " %sBased on THC hackerschoice/ToolsWeNeed%s\n", dim, reset)
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %sDomains: %s | DNS: %s | API: %s%s\n", green, strings.Join(domains, ", "), dnsAddr, apiAddr, reset)
	fmt.Fprintln(w)
}
