package main

import (
	"fmt"
	"os"

	"github.com/BlueLogicLabs/sealcheck"
	"github.com/fatih/color"
	"github.com/grantae/certinfo"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "sealcheck",
		Usage: "CLI utility for checking Planet seal proofs",
		Commands: []*cli.Command{
			{
				Name:  "validate",
				Usage: "validate a proof in JSON format",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "print-cert",
						Usage: "print certificate info",
					},
					&cli.StringFlag{
						Name:  "export-cert",
						Usage: "path to export the certificate to",
					},
				},
				ArgsUsage: "<path_to_json>",
				Action: func(c *cli.Context) error {
					jsonPath := c.Args().Get(0)
					color.Cyan("SealCheck: %s", jsonPath)

					jsonContent, err := os.ReadFile(jsonPath)
					if err != nil {
						return errors.Wrap(err, "failed to read json file")
					}

					svc := sealcheck.NewSealCheck()
					err = svc.ValidateJson(jsonContent)
					if err != nil {
						return errors.Wrap(err, "validation failed")
					}
					color.Green("Validation OK")
					cert := svc.Certificate

					if c.Bool("print-cert") {
						certInfo, err := certinfo.CertificateText(cert)
						if err != nil {
							return errors.Wrap(err, "failed to generate certificate info")
						}
						fmt.Printf("%s\n", certInfo)
					}

					exportCert := c.String("export-cert")
					if exportCert != "" {
						os.WriteFile(exportCert, cert.Raw, 0644)
						fmt.Printf("Certificate exported to %s.\n", exportCert)
					}
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		color.Red("Error: %+v", err)
		os.Exit(1)
	}
}
