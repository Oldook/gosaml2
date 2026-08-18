package saml2

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestEncryptedAssertionWithSkippedSignatureValidation(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./testdata/test.crt", "./testdata/test.key")
	require.NoError(t, err, "could not load x509 key pair")

	block, _ := pem.Decode([]byte(idpCert))
	idpCertificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse idp cert pem block")

	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: "https://saml2.test.astuart.co/sso/saml2",
		SPKeyStore:                  dsig.TLSCertKeyStore(cert),
		SkipSignatureValidation:     true,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idpCertificate},
		},
		Clock: dsig.NewFakeClockAt(time.Date(2016, 4, 28, 22, 0, 0, 0, time.UTC)),
	}

	bs, err := os.ReadFile("./testdata/saml.post")
	require.NoError(t, err, "couldn't read post")

	assertionInfo, err := sp.RetrieveAssertionInfo(string(bs))
	require.NoError(t, err, "encrypted assertion should be decrypted when signature validation is skipped")
	require.NotNil(t, assertionInfo)
}
