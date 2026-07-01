// Command tgconv converts Telegram session strings between library formats.
//
// Usage:
//
//	tgconv convert <string> -f <telethon|pyrogram|...> -t <target>
//	tgconv info <string> [-f <format>]
//	tgconv from-file <path> [-t <format>]
//	tgconv list
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tgconv "github.com/mtgo-labs/session-converter"
)

func usage() {
	fmt.Fprintln(os.Stderr, `tgconv — Telegram session string converter

Usage:
  tgconv convert <session-string> -t <format> [-f <format>] [flags]
  tgconv info <session-string> [-f <format>]
  tgconv from-file <sqlite-path> [-t <format>] [flags]
  tgconv generate --api-id <id> --api-hash <hash> [--bot-token <token> | --phone <number>] [-t <format>]
  tgconv list

Commands:
  convert     Convert a session string to another format (auto-detects source)
  info        Show decoded session information
  from-file   Read a SQLite session file and export as a string
  generate    Generate a new session by authenticating with Telegram
  list        List supported formats

Formats:
  telethon, pyrogram, gramjs, mtcute, mtkruto, gogram, gotgproto

Flags (convert):
  -f string   Source format (default: auto-detect)
  -t string   Target format (required)
  --api-id int          API ID (for pyrogram/mtcute output)
  --user-id int64       User ID (for pyrogram/mtcute output)
  --is-bot              Mark as bot account
  --test-mode           Connect to test servers

Flags (from-file):
  -t string   Target format (default: telethon)

Flags (generate):
  --api-id int          API ID from my.telegram.org (required)
  --api-hash string     API Hash from my.telegram.org (required)
  --bot-token string    Bot token (for bot sessions)
  --phone string        Phone number (for user sessions, e.g. +1234567890)
  -t string             Output format (default: telethon)`)
}

// reorderArgs moves all flag arguments to the front and positional args to
// the back, so Go's flag package can parse interspersed flags. Handles both
// "--flag value" and "--flag=value" forms.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			if strings.Contains(args[i], "=") {
				flags = append(flags, args[i])
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i], args[i+1])
				i++
			} else {
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	return append(flags, positional...)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "convert":
		cmdConvert(args)
	case "info":
		cmdInfo(args)
	case "from-file":
		cmdFromFile(args)
	case "list":
		cmdList()
	case "generate":
		cmdGenerate(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	from := fs.String("f", "", "source format (auto-detect)")
	to := fs.String("t", "", "target format")
	apiID := fs.Int64("api-id", 0, "API ID")
	userID := fs.Int64("user-id", 0, "user ID")
	isBot := fs.Bool("is-bot", false, "is bot")
	testMode := fs.Bool("test-mode", false, "test mode")
	fs.Parse(reorderArgs(args))

	rest := fs.Args()
	if len(rest) < 1 || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: tgconv convert <string> -t <format> [-f <format>]")
		os.Exit(1)
	}

	input := rest[0]
	target := tgconv.Format(*to)

	// Validate target format.
	if !validFormat(target) {
		fmt.Fprintf(os.Stderr, "error: unsupported target format %q\n", *to)
		os.Exit(1)
	}

	// Decode.
	var session *tgconv.Session
	var err error
	if *from != "" {
		source := tgconv.Format(*from)
		session, err = tgconv.DecodeFormat(input, source)
	} else {
		session, _, err = tgconv.Decode(input)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: decode: %v\n", err)
		os.Exit(1)
	}

	// Apply overrides.
	if *apiID > 0 {
		session.AppID = int32(*apiID)
	}
	if *userID > 0 {
		session.UserID = *userID
	}
	if *isBot {
		session.IsBot = true
	}
	if *testMode {
		session.TestMode = true
	}

	// Warn about missing fields.
	if (target == tgconv.FormatPyrogram || target == tgconv.FormatMtcute) && session.UserID == 0 {
		fmt.Fprintln(os.Stderr, "warning: user_id is 0 — pyrogram/mtcute output may be incomplete (use --user-id)")
	}
	if target == tgconv.FormatPyrogram && session.AppID == 0 {
		fmt.Fprintln(os.Stderr, "warning: api_id is 0 — pyrogram output may not work (use --api-id)")
	}

	// Encode.
	output, err := tgconv.Encode(session, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: encode: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(output)
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	from := fs.String("f", "", "source format (auto-detect)")
	fs.Parse(reorderArgs(args))

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tgconv info <string> [-f <format>]")
		os.Exit(1)
	}

	input := rest[0]
	var session *tgconv.Session
	var format tgconv.Format
	var err error

	if *from != "" {
		format = tgconv.Format(*from)
		session, err = tgconv.DecodeFormat(input, format)
	} else {
		session, format, err = tgconv.Decode(input)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Format:       %s\n", format)
	fmt.Printf("DC ID:        %d\n", session.DCID)
	fmt.Printf("Server:       %s:%d\n", session.ServerAddress, session.Port)
	fmt.Printf("Auth Key:     %d bytes (%s...)\n", len(session.AuthKey), hexPrefix(session.AuthKey, 16))
	fmt.Printf("API ID:       %d\n", session.AppID)
	fmt.Printf("Test Mode:    %v\n", session.TestMode)
	fmt.Printf("User ID:      %d\n", session.UserID)
	fmt.Printf("Is Bot:       %v\n", session.IsBot)
}

func cmdFromFile(args []string) {
	fs := flag.NewFlagSet("from-file", flag.ExitOnError)
	to := fs.String("t", "telethon", "target format")
	apiID := fs.Int64("api-id", 0, "API ID")
	userID := fs.Int64("user-id", 0, "user ID")
	isBot := fs.Bool("is-bot", false, "is bot")
	fs.Parse(reorderArgs(args))

	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: tgconv from-file <sqlite-path> [-t <format>]")
		os.Exit(1)
	}

	path := rest[0]
	session, sqliteFmt, err := tgconv.ReadSQLite(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "detected: %s sqlite session\n", sqliteFmt)

	if *apiID > 0 {
		session.AppID = int32(*apiID)
	}
	if *userID > 0 {
		session.UserID = *userID
	}
	if *isBot {
		session.IsBot = true
	}

	target := tgconv.Format(*to)
	if !validFormat(target) {
		fmt.Fprintf(os.Stderr, "error: unsupported format %q\n", *to)
		os.Exit(1)
	}

	output, err := tgconv.Encode(session, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(output)
}

func cmdList() {
	fmt.Println("Supported session formats:")
	for _, f := range tgconv.AllFormats {
		fmt.Printf("  %s\n", f)
	}
	fmt.Println()
	fmt.Println("SQLite file formats:")
	fmt.Println("  telethon  (.session)")
	fmt.Println("  pyrogram  (.session)")
}

func validFormat(f tgconv.Format) bool {
	for _, v := range tgconv.AllFormats {
		if v == f {
			return true
		}
	}
	return false
}

func hexPrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	var sb strings.Builder
	for i := range n {
		sb.WriteString(fmt.Sprintf("%02x", b[i]))
	}
	return sb.String()
}

