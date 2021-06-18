package provisionerbeta

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
	"go.step.sm/linkedca"
	"google.golang.org/protobuf/encoding/protojson"
)

func updateCommand() cli.Command {
	return cli.Command{
		Name:      "update",
		Action:    cli.ActionFunc(updateAction),
		Usage:     "update a provisioner",
		UsageText: `**step beta ca provisioner update** <name> [flags]`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "name",
				Usage: `The new <name> for the provisioner.`,
			},
			x509TemplateFlag,
			x509TemplateDataFlag,
			sshTemplateFlag,
			sshTemplateDataFlag,
			x509MinDurFlag,
			x509MaxDurFlag,
			x509DefaultDurFlag,
			sshUserMinDurFlag,
			sshUserMaxDurFlag,
			sshUserDefaultDurFlag,
			sshHostMinDurFlag,
			sshHostMaxDurFlag,
			sshHostDefaultDurFlag,
			disableRenewalFlag,
			enableX509Flag,
			enableSSHFlag,

			// JWK provisioner flags
			cli.BoolFlag{
				Name:  "create",
				Usage: `Create the JWK key pair for the provisioner.`,
			},
			cli.StringFlag{
				Name:  "private-key",
				Usage: `The <file> containing the JWK private key.`,
			},
			cli.StringFlag{
				Name:  "public-key",
				Usage: `The <file> containing the JWK public key.`,
			},

			// OIDC provisioner flags
			cli.StringFlag{
				Name:  "client-id",
				Usage: `The <id> used to validate the audience in an OpenID Connect token.`,
			},
			cli.StringFlag{
				Name:  "client-secret",
				Usage: `The <secret> used to obtain the OpenID Connect tokens.`,
			},
			cli.StringFlag{
				Name:  "listen-address",
				Usage: `The callback <address> used in the OpenID Connect flow (e.g. \":10000\")`,
			},
			cli.StringFlag{
				Name:  "configuration-endpoint",
				Usage: `OpenID Connect configuration <url>.`,
			},
			cli.StringSliceFlag{
				Name: "admin",
				Usage: `The <email> of an admin user in an OpenID Connect provisioner, this user
will not have restrictions in the certificates to sign. Use the
'--admin' flag multiple times to configure multiple administrators.`,
			},
			cli.StringSliceFlag{
				Name: "group",
				Usage: `The <group> list used to validate the groups extenstion in an OpenID Connect token.
Use the '--group' flag multiple times to configure multiple groups.`,
			},
			cli.StringFlag{
				Name:  "tenant-id",
				Usage: `The <tenant-id> used to replace the templatized {tenantid} in the OpenID Configuration.`,
			},

			// X5C provisioner flags
			cli.StringFlag{
				Name: "x5c-root",
				Usage: `Root certificate (chain) <file> used to validate the signature on X5C
provisioning tokens.`,
			},
			// ACME provisioner flags
			forceCNFlag,

			flags.X5cCert,
			flags.X5cKey,
			flags.PasswordFile,
			flags.CaURL,
			flags.Root,
		},
		Description: `**step ca provisioner update** updates a provisioner.

## POSITIONAL ARGUMENTS

<name>
: The name of the provisioner.

## EXAMPLES

Update a JWK provisioner with a new key pair, adjusted claims, and a new x509 template:
'''
step beta ca provisioner update admin-jwk --create \
	--x509-min-dur 4m --x509-default-dur 13h --x509-template ./templates/x509-example.tpl
'''`,
	}
}

func updateAction(ctx *cli.Context) (err error) {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	args := ctx.Args()
	name := args[0]

	// Create online client
	client, err := cautils.NewAdminClient(ctx)
	if err != nil {
		return err
	}

	p, err := client.GetProvisioner(ca.WithProvisionerName(name))
	if err != nil {
		return err
	}

	if ctx.IsSet("name") {
		p.Name = ctx.String("name")
	}
	if err := updateTemplates(ctx, p); err != nil {
		return err
	}
	updateClaims(ctx, p)

	switch p.Type {
	case linkedca.Provisioner_JWK:
		err = updateJWKDetails(ctx, p)
	case linkedca.Provisioner_ACME:
		err = updateACMEDetails(ctx, p)
	case linkedca.Provisioner_SSHPOP:
		err = updateSSHPOPDetails(ctx, p)
	case linkedca.Provisioner_X5C:
		err = updateX5CDetails(ctx, p)
	case linkedca.Provisioner_K8SSA:
		err = updateK8SSADetails(ctx, p)
	case linkedca.Provisioner_OIDC:
		err = updateOIDCDetails(ctx, p)
	// TODO add GCP, Azure, AWS, and SCEP provisioner support.
	default:
		return fmt.Errorf("unsupported provisioner type %s", p.Type.String())
	}
	if err != nil {
		return err
	}

	if err = client.UpdateProvisioner(name, p); err != nil {
		return err
	}

	var buf bytes.Buffer
	b, err := protojson.Marshal(p)
	if err != nil {
		return err
	}
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return err
	}
	fmt.Println(buf.String())

	return nil
}

func updateTemplates(ctx *cli.Context, p *linkedca.Provisioner) error {
	// Read x509 template if passed
	if p.X509Template == nil {
		p.X509Template = &linkedca.Template{}
	}
	if x509TemplateFile := ctx.String("x509-template"); ctx.IsSet("x509-template") {
		b, err := utils.ReadFile(x509TemplateFile)
		if err != nil {
			return err
		}
		p.X509Template.Template = b
	}
	if x509TemplateDataFile := ctx.String("x509-template-data"); ctx.IsSet("x509-template-data") {
		b, err := utils.ReadFile(x509TemplateDataFile)
		if err != nil {
			return err
		}
		p.X509Template.Data = b
	}
	// Read ssh template if passed
	if p.SshTemplate == nil {
		p.SshTemplate = &linkedca.Template{}
	}
	if sshTemplateFile := ctx.String("ssh-template"); ctx.IsSet("ssh-template") {
		b, err := utils.ReadFile(sshTemplateFile)
		if err != nil {
			return err
		}
		p.SshTemplate.Template = b
	}
	if sshTemplateDataFile := ctx.String("ssh-template-data"); ctx.IsSet("ssh-template-data") {
		b, err := utils.ReadFile(sshTemplateDataFile)
		if err != nil {
			return err
		}
		p.SshTemplate.Data = b
	}
	return nil
}

func updateClaims(ctx *cli.Context, p *linkedca.Provisioner) {
	if p.Claims == nil {
		p.Claims = &linkedca.Claims{}
	}
	if ctx.IsSet("disable-renewal") {
		p.Claims.DisableRenewal = ctx.Bool("disable-renewal")
	}
	xc := p.Claims.X509
	if xc == nil {
		xc = &linkedca.X509Claims{}
	}
	if ctx.IsSet("x509") {
		xc.Enabled = ctx.Bool("x509")
	}
	d := xc.Durations
	if d == nil {
		d = &linkedca.Durations{}
	}
	if ctx.IsSet("x509-min-dur") {
		d.Min = ctx.String("x509-min-dur")
	}
	if ctx.IsSet("x509-max-dur") {
		d.Max = ctx.String("x509-max-dur")
	}
	if ctx.IsSet("x509-default-dur") {
		d.Default = ctx.String("x509-default-dur")
	}

	sc := p.Claims.Ssh
	if sc == nil {
		sc = &linkedca.SSHClaims{}
	}
	if ctx.IsSet("ssh") {
		sc.Enabled = ctx.Bool("ssh")
	}
	d = sc.UserDurations
	if d == nil {
		d = &linkedca.Durations{}
	}
	if ctx.IsSet("ssh-user-min-dur") {
		d.Min = ctx.String("ssh-user-min-dur")
	}
	if ctx.IsSet("ssh-user-max-dur") {
		d.Max = ctx.String("ssh-user-max-dur")
	}
	if ctx.IsSet("ssh-user-default-dur") {
		d.Default = ctx.String("ssh-user-default-dur")
	}
	d = sc.HostDurations
	if d == nil {
		d = &linkedca.Durations{}
	}
	if ctx.IsSet("ssh-host-min-dur") {
		d.Min = ctx.String("ssh-host-min-dur")
	}
	if ctx.IsSet("ssh-host-max-dur") {
		d.Max = ctx.String("ssh-host-max-dur")
	}
	if ctx.IsSet("ssh-host-default-dur") {
		d.Default = ctx.String("ssh-host-default-dur")
	}
}

func updateJWKDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	/*
		var (
			err      error
			password string
		)
		if passwordFile := ctx.String("password-file"); len(passwordFile) > 0 {
			password, err = utils.ReadStringPasswordFromFile(passwordFile)
			if err != nil {
				return nil, err
			}
		}

		var (
			jwk *jose.JSONWebKey
			jwe *jose.JSONWebEncryption
		)
		if ctx.Bool("create") {
			if ctx.IsSet("public-key") {
				return nil, errs.IncompatibleFlag(ctx, "create", "public-key")
			}
			if ctx.IsSet("private-key") {
				return nil, errs.IncompatibleFlag(ctx, "create", "private-key")
			}
			pass, err := ui.PromptPasswordGenerate("Please enter a password to encrypt the provisioner private key? [leave empty and we'll generate one]", ui.WithValue(password))
			if err != nil {
				return nil, err
			}
			jwk, jwe, err = jose.GenerateDefaultKeyPair(pass)
			if err != nil {
				return nil, err
			}
		} else {
			var jwkFile string
			if ctx.IsSet("public-key") && ctx.IsSet("private-key") {
				return nil, errs.IncompatibleFlag(ctx, "public-key", "private-key")
			} else if !ctx.IsSet("public-key") && !ctx.IsSet("private-key") {
				return nil, errs.RequiredWithOrFlag(ctx, "public-key", "private-key")
			} else if ctx.IsSet("public-key") {
				jwkFile = ctx.String("public-key")
				jwk, err = jose.ParseKey(jwkFile)
			} else {
				jwkFile = ctx.String("private-key")
				jwk, err = jose.ParseKey(jwkFile)
			}
			if err != nil {
				return nil, errs.FileError(err, jwkFile)
			}
			// Only use asymmetric cryptography
			if _, ok := jwk.Key.([]byte); ok {
				return nil, errors.New("invalid JWK: a symmetric key cannot be used as a provisioner")
			}
			// Create kid if not present
			if len(jwk.KeyID) == 0 {
				jwk.KeyID, err = jose.Thumbprint(jwk)
				if err != nil {
					return nil, err
				}
			}

			if !jwk.IsPublic() {
				// Encrypt JWK
				jwe, err = jose.EncryptJWK(jwk)
				if err != nil {
					return nil, err
				}
			}
		}
		jwkPubBytes, err := jwk.MarshalJSON()
		if err != nil {
			return nil, errors.Wrap(err, "error marshaling JWK")
		}
		jwkProv := &linkedca.JWKProvisioner{
			PublicKey: jwkPubBytes,
		}

		if jwe != nil {
			jwePrivStr, err := jwe.CompactSerialize()
			if err != nil {
				return nil, errors.Wrap(err, "error serializing JWE")
			}
			jwkProv.EncryptedPrivateKey = []byte(jwePrivStr)
		}

		return &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: jwkProv,
			},
		}, nil
	*/
	return nil
}

func updateACMEDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_ACME)
	if !ok {
		return errors.New("error casting details to ACME type")
	}
	details := data.ACME
	if ctx.IsSet("force-cn") {
		details.ForceCn = ctx.Bool("force-cn")
	}
	return nil
}

func updateSSHPOPDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	return nil
}

func updateX5CDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_X5C)
	if !ok {
		return errors.New("error casting details to X5C type")
	}
	details := data.X5C
	if ctx.IsSet("x5c-root") {
		x5cRootFile := ctx.String("x5c-root")
		roots, err := pemutil.ReadCertificateBundle(x5cRootFile)
		if err != nil {
			return errors.Wrapf(err, "error loading X5C Root certificates from %s", x5cRootFile)
		}
		var rootBytes [][]byte
		for _, r := range roots {
			if r.KeyUsage&x509.KeyUsageCertSign == 0 {
				return errors.Errorf("error: certificate with common name '%s' cannot be "+
					"used as an X5C root certificate.\n\n"+
					"X5C provisioner root certificates must have the 'Certificate Sign' key "+
					"usage extension.", r.Subject.CommonName)
			}
			rootBytes = append(rootBytes, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: r.Raw,
			}))
		}
		details.Roots = rootBytes
	}
	return nil
}

func updateK8SSADetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_K8SSA)
	if !ok {
		return errors.New("error casting details to K8SSA type")
	}
	details := data.K8SSA
	if ctx.IsSet("public-key") {
		pemKeysF := ctx.String("public-key")
		pemKeysB, err := ioutil.ReadFile(pemKeysF)
		if err != nil {
			return errors.Wrap(err, "error reading pem keys")
		}

		var (
			block   *pem.Block
			rest    = pemKeysB
			pemKeys = []interface{}{}
		)
		for rest != nil {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			key, err := pemutil.ParseKey(pem.EncodeToMemory(block))
			if err != nil {
				return errors.Wrapf(err, "error parsing public key from %s", pemKeysF)
			}
			switch q := key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			default:
				return errors.Errorf("Unexpected public key type %T in %s", q, pemKeysF)
			}
			pemKeys = append(pemKeys, key)
		}

		var pubKeyBytes [][]byte
		for _, k := range pemKeys {
			blk, err := pemutil.Serialize(k)
			if err != nil {
				return errors.Wrap(err, "error serializing pem key")
			}
			pubKeyBytes = append(pubKeyBytes, pem.EncodeToMemory(blk))
		}
		details.PublicKeys = pubKeyBytes
	}
	return nil
}

func updateOIDCDetails(ctx *cli.Context, p *linkedca.Provisioner) error {
	data, ok := p.Details.GetData().(*linkedca.ProvisionerDetails_OIDC)
	if !ok {
		return errors.New("error casting details to OIDC type")
	}
	details := data.OIDC
	if ctx.IsSet("client-id") {
		details.ClientId = ctx.String("client-id")
	}
	if ctx.IsSet("client-secret") {
		details.ClientSecret = ctx.String("client-secret")
	}
	if ctx.IsSet("admin") {
		details.Admins = ctx.StringSlice("admin")
	}
	if ctx.IsSet("domain") {
		details.Domains = ctx.StringSlice("domain")
	}
	if ctx.IsSet("group") {
		details.Groups = ctx.StringSlice("group")
	}
	if ctx.IsSet("listen-address") {
		details.ListenAddress = ctx.String("listen-address")
	}
	if ctx.IsSet("tenant-id") {
		details.TenantId = ctx.String("tenant-id")
	}
	if ctx.IsSet("configuration-endpoint") {
		ce := ctx.String("configuration-endpoint")
		u, err := url.Parse(ce)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return errs.InvalidFlagValue(ctx, "configuration-endpoint", ce, "")
		}
		details.ConfigurationEndpoint = ce
	}
	return nil
}
