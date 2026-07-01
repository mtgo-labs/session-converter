package main

import (
	"flag"
	"fmt"
	"os"

	tgconv "github.com/mtgo-labs/session-converter"
	"github.com/mtgo-labs/mtgo/telegram"
)

func cmdGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	apiID := fs.Int64("api-id", 0, "API ID from my.telegram.org (required)")
	apiHash := fs.String("api-hash", "", "API Hash from my.telegram.org (required)")
	botToken := fs.String("bot-token", "", "Bot token (for bot sessions)")
	phone := fs.String("phone", "", "Phone number in international format (for user sessions)")
	to := fs.String("t", "telethon", "output format")
	fs.Parse(reorderArgs(args))

	if *apiID == 0 || *apiHash == "" {
		fmt.Fprintln(os.Stderr, "error: --api-id and --api-hash are required")
		os.Exit(1)
	}
	if *botToken == "" && *phone == "" {
		fmt.Fprintln(os.Stderr, "error: provide either --bot-token or --phone")
		os.Exit(1)
	}

	target := tgconv.Format(*to)
	if !validFormat(target) {
		fmt.Fprintf(os.Stderr, "error: unsupported format %q\n", *to)
		os.Exit(1)
	}



	cfg := &telegram.Config{
		APIID:     int32(*apiID),
		APIHash:   *apiHash,
		InMemory:  true,
		NoUpdates: true,
	}

	if *botToken != "" {
		cfg.BotToken = *botToken
		fmt.Fprintln(os.Stderr, "connecting as bot...")
	} else {
		cfg.PhoneNumber = *phone
		cfg.CodeFunc = telegram.TerminalCodeFunc()
		cfg.PasswordFunc = telegram.TerminalPasswordFunc()
		fmt.Fprintf(os.Stderr, "connecting as user (%s)...\n", *phone)
	}

	client, err := telegram.NewClient(int32(*apiID), *apiHash, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create client: %v\n", err)
		os.Exit(1)
	}

	if err := client.Connect(0); err != nil {
		fmt.Fprintf(os.Stderr, "error: connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Stop()

	// Export session string (Pyrogram format from mtgo).
	pyroStr, err := client.ExportSessionString()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: export session: %v\n", err)
		os.Exit(1)
	}

	if pyroStr == "" {
		fmt.Fprintln(os.Stderr, "error: authentication failed — empty session")
		os.Exit(1)
	}

	// Convert to the requested format.
	output := pyroStr
	if target != tgconv.FormatPyrogram {
		output, err = tgconv.Convert(pyroStr, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: convert to %s: %v\n", target, err)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "session generated successfully")
	fmt.Println(output)
}
