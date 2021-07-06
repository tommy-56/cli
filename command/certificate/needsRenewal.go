package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultPercentUsedThreshold = 66

func needsRenewalCommand() cli.Command {
	return cli.Command{
		Name:      "needs-renewal",
		Action:    cli.ActionFunc(needsRenewalAction),
		Usage:     `Check if a certificate needs to be renewed`,
		UsageText: `**step certificate needs-renewal** <crt_file or host_name> [**--expires-in**=<duration>]`,
		Description: `**step certificate needs-renewal** returns '0' if the certificate needs to be renewed based on it's remaining lifetime. 
		Returns '1' if the certificate is within it's validity lifetime bounds and does not need to be renewed. 
		Returns '255' for any other error. By default, if a certificate "needs renewal" when it has passed 66% of it's allotted lifetime. 
		This threshold can be adjusted using the '--expires-in' flag.
## POSITIONAL ARGUMENTS
<cert_file or hostname> The path to a certificate to validate OR a hostname with protocol prefix.

## EXIT CODES

This command returns '0' if the certificate needs renewal, '1' if the certificate does not need renewal, and '255' for any error.

## EXAMPLES
Check certificate for renewal using custom directory: 
'''
$ step certificate needs-renewal ./certificate.crt 
'''
Check certificate for renewal using a hostname:
$ step certificate needs-renewal https://smallstep.com
'''
Check if certificate will expire within a given time:
$ step certificate needs-renewal ./certificate.crt --expires-in 1h15m
'''
Check if certificate from hostname will expire within a given time:
$ step certificate needs-renewal https://smallstep.com --expires-in 1h15m
'''
Check if certificate has passed a percentage of its lifetime: 
$ step certificate needs-renewal ./certificate.crt --expires-in 75%
'''
Check if certificate from a hostname has passed a percentage of its lifetime:
$ step certificate needs-renewal https://smallstep.com --expires-in 75%
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "expires-in",
				Usage: `Check if the certificate expires in given time duration
				using <percent|duration>. With <percent>, must be followed by "%".
				With <duration>, it is a sequence of decimal numbers, each with optional
				fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m". Valid
				time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`,
			},
		},
	}
}

func needsRenewalAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}
	var (
		crtFile    = ctx.Args().Get(0)
		expiresIn  = ctx.String("expires-in")
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
		//cert       *x509.Certificate
	)

	var blocks []*pem.Block
	var block *pem.Block
	if addr, isURL, err := trimURL(crtFile); err != nil {
		return errs.NewExitError(err, 255)
	} else if isURL {
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, false)
		if err != nil {
			return errs.NewExitError(err, 255)
		}
		for _, crt := range peerCertificates {
			blocks = append(blocks, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: crt.Raw,
			})
		}

	} else {
		crtBytes, err := ioutil.ReadFile(crtFile)
		if err != nil {
			return errs.NewExitError(err, 255)
		}

		// The first certificate PEM in the file is our leaf Certificate.
		// Any certificate after the first is added to the list of Intermediate
		// certificates used for path validation.
		for len(crtBytes) > 0 { //error check here similar to instpect.go changing cert.ect to each block of array
			block, crtBytes = pem.Decode(crtBytes)
			if block == nil {
				return errs.NewExitError(errors.Errorf("%s contains an invalid PEM block", crtFile), 255)
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			//if block == nil {
			//	blocks, err = x509.ParseCertificate(block.Bytes)
			//	if err != nil {
			//		return errs.NewExitError(errors.WithStack(err), 255)
			//	}
			//}
			blocks = append(blocks, block)
		}
		if block == nil {
			return errs.NewExitError(errors.Errorf("%s contains no PEM certificate blocks", crtFile), 255)
		}

	}
	//new For loop to run these checks and math against each block
	renew := false
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errs.NewExitError(errors.WithStack(err), 255)
		}
		var remainingValidity = time.Until(cert.NotAfter)
		var totalValidity = cert.NotAfter.Sub(cert.NotBefore)
		var percentUsed = (1 - remainingValidity.Minutes()/totalValidity.Minutes()) * 100

		if expiresIn != "" {
			if strings.Contains(expiresIn, "%") {
				percentageInput, err := strconv.Atoi(strings.TrimSuffix(expiresIn, "%"))

				if err != nil {
					return errs.NewExitError(err, 255)
				}
				if percentageInput > 100 || percentageInput < 0 {
					return errs.NewExitError(errors.Errorf("Percentage must be in range 0-100"), 255)
				}

				//if percentageInput > int(percentUsed) {
				//	//os.Exit(1)
				//	//continue
				//	renew = true
				//}

			} else {
				duration, err := time.ParseDuration(expiresIn)

				if err != nil {
					return errs.NewExitError(err, 255)
				} else if duration.Minutes() > remainingValidity.Minutes() {
					//return nil
					renew = true
				}
				//os.Exit(1)
			}
		} else {
			if percentUsed >= defaultPercentUsedThreshold {
				//return nil
				renew = true
			} else if percentUsed < defaultPercentUsedThreshold {
				//os.Exit(1)
				continue
			} else {
				return errs.NewExitError(errors.Errorf("Can not determine remaining lifetime on certificate %s", crtFile), 255)
			}
		}
	}
	//Can't return nil or os.Exit without breaking loop
	if renew {
		return nil //exit code 0
	} else {
		os.Exit(1)
	}

	return nil
}
