package main

import (
	"fmt"
	"os"
	"time"

	"github.com/TALLHAMADOU/gotemper"
	"github.com/urfave/cli/v2"
)

var version = "0.1.0"

func main() {
	app := &cli.App{
		Name:    "gotemper",
		Usage:   "Outil de test de résilience & sécurité pour vos services HTTP",
		Version: version,
		Commands: []*cli.Command{
			checkCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "erreur:", err)
		os.Exit(1)
	}
}

func checkCommand() *cli.Command {
	return &cli.Command{
		Name:  "check",
		Usage: "Vérifie la présence des headers de sécurité sur une cible",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "url", Required: true, Usage: "URL cible (ex: https://api.example.com)"},
			&cli.BoolFlag{Name: "fuzz", Usage: "Envoie les payloads d'edge-case courants (CommonEdgeCases) pour tester la robustesse"},
			&cli.StringFlag{Name: "fuzz-param", Value: "input", Usage: "Nom du paramètre de requête utilisé pour le fuzzing"},
			&cli.BoolFlag{Name: "fail-on-critical", Usage: "Termine avec un code non nul si un finding critique est trouvé"},
		},
		Action: func(c *cli.Context) error {
			scenario := gotemper.NewScenario("api-check").
				Target(c.String("url")).
				CheckHeaders(gotemper.SecurityHeaders).
				RateLimit(100, time.Second)

			if c.Bool("fuzz") {
				scenario = scenario.
					FuzzInputs(gotemper.CommonEdgeCases).
					FuzzParam(c.String("fuzz-param"))
			}

			report := gotemper.Run(scenario)

			fmt.Printf("🔍 GoTemper — scénario %q sur %s\n", report.Scenario, c.String("url"))
			if len(report.Findings) == 0 {
				fmt.Println("✅ Aucun finding.")
				return nil
			}
			for _, f := range report.Findings {
				fmt.Printf("  [%s] %s\n", f.Severity, f.Message)
			}

			if c.Bool("fail-on-critical") {
				report.FailBuildIfCritical()
			}
			return nil
		},
	}
}
