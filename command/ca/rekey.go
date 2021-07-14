package ca

import (
	//"fmt"

	"bytes"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	"github.com/smallstep/cli/utils/cautils"
	"net/url"

	//"github.com/pkg/errors"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/certificates/pki"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
	"net/http"
)

func rekeyCertificateCommand() cli.Command {
	return cli.Command{
		Name:      "rekey",
		Action:    command.ActionFunc(rekeyCertificateAction),
		Usage:     "rekey a valid certificate",
		UsageText: `**step ca rekey**`,
		Description: `
**step ca rekey** command rekeys the given certificate

## POSITIONAL ARGUMENTS

<crt-file>
:  The certificate in PEM format that we want to renew.

<key-file>
:  They key file of the certificate.

## EXAMPLES

Rekey a certificate
'''
$ step ca rekey
'''`,
		Flags: []cli.Flag{
			flags.Root,
			cli.StringFlag{
				Name:  "A flag",
				Usage: "what it does",
			},
		},
	}
}

func rekeyCertificateAction(ctx *cli.Context) error {
	err := errs.NumberOfArguments(ctx, 2)
	if err != nil {
		return err
	}
	args := ctx.Args()
	// get pub key from certificate
	//can I combine both into a single function instead?
	pubName := args().Get(0)
	a, err := utils.ReadFile(pubName)
	if err != nil {
		return err
	}
	pub, err := pemutil.ParseKey(a, pemutil.WithFirstBlock())
	if err != nil {
		return err
	}
	//necessary?
	/*pubBlock, err := pemutil.Serialize(pub)
	if err != nil {
		return err
	}*/
	//fmt.Print(string(pem.EncodeToMemory(pubBlock)))

	// get public key from private
	privateName := args().Get(1)
	b, err := utils.ReadFile(privateName)
	if err != nil {
		return err
	}
	key, err := pemutil.ParseKey(b, pemutil.WithFirstBlock())
	if err != nil {
		return err
	}
	//is this necessary?
	/*privBlock, err := pemutil.Serialize(key)
	if err != nil {
		return err
	}*/
	//fmt.Print(string(pem.EncodeToMemory(privBlock)))

	if pub == key {
		//if pubBlock == privBlock {
		//start replacing keys - need to call function here
		cer := req *api.RekeyRequest
		replace := tr http.RoundTripper
		key, err := ca.Rekey(cer, replace)
		if err != nil {
			return err
		}
		fmt.printf(key)
		/*RekeyRequest(privateName)
		if err = b.Rekey(req *api.RekeyRequest, tr http.RoundTripper) (*api.SignResponse, error))

		//from api/rekey.go in certificates
		type RekeyRequest struct {
			CsrPEM CertificateRequest `json:"csr"`
		}

		// Validate checks the fields of the RekeyRequest and returns nil if they are ok
		// or an error if something is wrong.
		func (s *RekeyRequest) Validate() error {
			if s.CsrPEM.CertificateRequest == nil {
			return errs.BadRequest("missing csr")
		}
			if err := s.CsrPEM.CertificateRequest.CheckSignature(); err != nil {
			return errs.Wrap(http.StatusBadRequest, err, "invalid csr")
		}
			func (h *caHandler) Rekey(w http.ResponseWriter, r *http.Request){
		}
		}*/
	} else {
		print("Public key does not match with private key file given. ")
	}
	return nil
}
type rekeyer struct {
	client    cautils.CaClient
	transport *http.Transport
	key       crypto.PrivateKey
	offline   bool
}

func (r *rekeyer) Rekey(req *api.RekeyRequest, tr http.RoundTripper) (*api.SignResponse, error) {
	var retried bool
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling request")
	}

	u := r.endpoint.ResolveReference(&url.URL{Path: "/rekey"})
	client := &http.Client{Transport: tr}
retry:
	resp, err := client.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Rekey; client POST %s failed", u)
	}
	if resp.StatusCode >= 400 {
		if !retried && r.retryOnError(resp) {
			retried = true
			goto retry
		}
		return nil, readError(resp.Body)
	}
	var sign api.SignResponse
	if err := readJSON(resp.Body, &sign); err != nil {
		return nil, errs.Wrapf(http.StatusInternalServerError, err, "client.Rekey; error reading %s", u)
	}
	return &sign, nil
}

func (r *renewer) Renew(outFile string) (*api.SignResponse, error) {
	resp, err := r.client.Renew(r.transport)
	if err != nil {
		return nil, errors.Wrap(err, "error renewing certificate")
	}

	if resp.CertChainPEM == nil || len(resp.CertChainPEM) == 0 {
		resp.CertChainPEM = []api.Certificate{resp.ServerPEM, resp.CaPEM}
	}
	var data []byte
	for _, certPEM := range resp.CertChainPEM {
		pemblk, err := pemutil.Serialize(certPEM.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "error serializing certificate PEM")
		}
		data = append(data, pem.EncodeToMemory(pemblk)...)
	}
	if err := utils.WriteFile(outFile, data, 0600); err != nil {
		return nil, errs.FileError(err, outFile)
	}

	return resp, nil
}
