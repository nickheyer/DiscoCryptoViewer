//go:build js && wasm

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strings"
	"time"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Scalar / primitive converters
// ---------------------------------------------------------------------------

func convertBigInt(n *big.Int) *pb.BigInt {
	if n == nil {
		return nil
	}
	return &pb.BigInt{Value: n.Bytes()}
}

func convertOID(oid asn1.ObjectIdentifier) *pb.ObjectIdentifier {
	return &pb.ObjectIdentifier{DotNotation: oid.String()}
}

func convertOIDs(oids []asn1.ObjectIdentifier) []*pb.ObjectIdentifier {
	out := make([]*pb.ObjectIdentifier, len(oids))
	for i, o := range oids {
		out[i] = convertOID(o)
	}
	return out
}

func convertValidity(notBefore, notAfter time.Time) *pb.Validity {
	return &pb.Validity{
		NotBefore: timestamppb.New(notBefore),
		NotAfter:  timestamppb.New(notAfter),
	}
}

func computeFingerprints(der []byte) *pb.Fingerprints {
	s256 := sha256.Sum256(der)
	s1 := sha1.Sum(der)
	m5 := md5.Sum(der)
	return &pb.Fingerprints{
		Sha256: s256[:],
		Sha1:   s1[:],
		Md5:    m5[:],
	}
}

// ---------------------------------------------------------------------------
// Distinguished name
// ---------------------------------------------------------------------------

func convertDN(name pkix.Name) *pb.DistinguishedName {
	dn := &pb.DistinguishedName{
		Country:            name.Country,
		Organization:       name.Organization,
		OrganizationalUnit: name.OrganizationalUnit,
		Locality:           name.Locality,
		Province:           name.Province,
		StreetAddress:      name.StreetAddress,
		PostalCode:         name.PostalCode,
		CommonName:         name.CommonName,
		SerialNumber:       name.SerialNumber,
	}
	for _, attr := range name.ExtraNames {
		dn.ExtraNames = append(dn.ExtraNames, &pb.AttributeTypeAndValue{
			Type:  convertOID(attr.Type),
			Value: attrValueString(attr.Value),
		})
	}
	return dn
}

func attrValueString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

func convertExtensions(exts []pkix.Extension) []*pb.Extension {
	out := make([]*pb.Extension, len(exts))
	for i, e := range exts {
		out[i] = &pb.Extension{
			Id:       convertOID(e.Id),
			Critical: e.Critical,
			Value:    e.Value,
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// SPKI
// ---------------------------------------------------------------------------

func convertSPKI(raw []byte) *pb.SubjectPublicKeyInfo {
	if len(raw) == 0 {
		return nil
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return &pb.SubjectPublicKeyInfo{PublicKey: &pb.BitString{Bytes: raw}}
	}
	return &pb.SubjectPublicKeyInfo{
		Algorithm: &pb.AlgorithmIdentifier{
			Algorithm:  convertOID(spki.Algorithm.Algorithm),
			Parameters: spki.Algorithm.Parameters.FullBytes,
		},
		PublicKey: &pb.BitString{
			Bytes:     spki.PublicKey.Bytes,
			BitLength: int32(spki.PublicKey.BitLength),
		},
	}
}

// ---------------------------------------------------------------------------
// Algorithm enums
// ---------------------------------------------------------------------------

var sigAlgMap = map[x509.SignatureAlgorithm]pb.SignatureAlgorithm{
	x509.MD2WithRSA:       pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_MD2_WITH_RSA,
	x509.MD5WithRSA:       pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_MD5_WITH_RSA,
	x509.SHA1WithRSA:      pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA1_WITH_RSA,
	x509.SHA256WithRSA:    pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA256_WITH_RSA,
	x509.SHA384WithRSA:    pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA384_WITH_RSA,
	x509.SHA512WithRSA:    pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA512_WITH_RSA,
	x509.DSAWithSHA1:      pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_DSA_WITH_SHA1,
	x509.DSAWithSHA256:    pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_DSA_WITH_SHA256,
	x509.ECDSAWithSHA1:    pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA1,
	x509.ECDSAWithSHA256:  pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256,
	x509.ECDSAWithSHA384:  pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384,
	x509.ECDSAWithSHA512:  pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512,
	x509.PureEd25519:      pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
	x509.SHA256WithRSAPSS: pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA256_WITH_RSA_PSS,
	x509.SHA384WithRSAPSS: pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA384_WITH_RSA_PSS,
	x509.SHA512WithRSAPSS: pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA512_WITH_RSA_PSS,
}

func convertSignatureAlgorithm(sa x509.SignatureAlgorithm) pb.SignatureAlgorithm {
	if v, ok := sigAlgMap[sa]; ok {
		return v
	}
	return pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
}

var pubKeyAlgMap = map[x509.PublicKeyAlgorithm]pb.PublicKeyAlgorithm{
	x509.RSA:     pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_RSA,
	x509.DSA:     pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_DSA,
	x509.ECDSA:   pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ECDSA,
	x509.Ed25519: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ED25519,
}

func convertPublicKeyAlgorithm(pka x509.PublicKeyAlgorithm) pb.PublicKeyAlgorithm {
	if v, ok := pubKeyAlgMap[pka]; ok {
		return v
	}
	return pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED
}

// ---------------------------------------------------------------------------
// Key usage
// ---------------------------------------------------------------------------

func convertKeyUsages(ku x509.KeyUsage) []pb.KeyUsage {
	pairs := []struct {
		bit x509.KeyUsage
		val pb.KeyUsage
	}{
		{x509.KeyUsageDigitalSignature, pb.KeyUsage_KEY_USAGE_DIGITAL_SIGNATURE},
		{x509.KeyUsageContentCommitment, pb.KeyUsage_KEY_USAGE_CONTENT_COMMITMENT},
		{x509.KeyUsageKeyEncipherment, pb.KeyUsage_KEY_USAGE_KEY_ENCIPHERMENT},
		{x509.KeyUsageDataEncipherment, pb.KeyUsage_KEY_USAGE_DATA_ENCIPHERMENT},
		{x509.KeyUsageKeyAgreement, pb.KeyUsage_KEY_USAGE_KEY_AGREEMENT},
		{x509.KeyUsageCertSign, pb.KeyUsage_KEY_USAGE_CERT_SIGN},
		{x509.KeyUsageCRLSign, pb.KeyUsage_KEY_USAGE_CRL_SIGN},
		{x509.KeyUsageEncipherOnly, pb.KeyUsage_KEY_USAGE_ENCIPHER_ONLY},
		{x509.KeyUsageDecipherOnly, pb.KeyUsage_KEY_USAGE_DECIPHER_ONLY},
	}
	var out []pb.KeyUsage
	for _, p := range pairs {
		if ku&p.bit != 0 {
			out = append(out, p.val)
		}
	}
	return out
}

var extKeyUsageMap = map[x509.ExtKeyUsage]pb.ExtKeyUsage{
	x509.ExtKeyUsageAny:                            pb.ExtKeyUsage_EXT_KEY_USAGE_ANY,
	x509.ExtKeyUsageServerAuth:                     pb.ExtKeyUsage_EXT_KEY_USAGE_SERVER_AUTH,
	x509.ExtKeyUsageClientAuth:                     pb.ExtKeyUsage_EXT_KEY_USAGE_CLIENT_AUTH,
	x509.ExtKeyUsageCodeSigning:                    pb.ExtKeyUsage_EXT_KEY_USAGE_CODE_SIGNING,
	x509.ExtKeyUsageEmailProtection:                pb.ExtKeyUsage_EXT_KEY_USAGE_EMAIL_PROTECTION,
	x509.ExtKeyUsageIPSECEndSystem:                 pb.ExtKeyUsage_EXT_KEY_USAGE_IPSEC_END_SYSTEM,
	x509.ExtKeyUsageIPSECTunnel:                    pb.ExtKeyUsage_EXT_KEY_USAGE_IPSEC_TUNNEL,
	x509.ExtKeyUsageIPSECUser:                      pb.ExtKeyUsage_EXT_KEY_USAGE_IPSEC_USER,
	x509.ExtKeyUsageTimeStamping:                   pb.ExtKeyUsage_EXT_KEY_USAGE_TIME_STAMPING,
	x509.ExtKeyUsageOCSPSigning:                    pb.ExtKeyUsage_EXT_KEY_USAGE_OCSP_SIGNING,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     pb.ExtKeyUsage_EXT_KEY_USAGE_MICROSOFT_SERVER_GATED_CRYPTO,
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      pb.ExtKeyUsage_EXT_KEY_USAGE_NETSCAPE_SERVER_GATED_CRYPTO,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: pb.ExtKeyUsage_EXT_KEY_USAGE_MICROSOFT_COMMERCIAL_CODE_SIGNING,
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     pb.ExtKeyUsage_EXT_KEY_USAGE_MICROSOFT_KERNEL_CODE_SIGNING,
}

func convertExtKeyUsages(ekus []x509.ExtKeyUsage) []pb.ExtKeyUsage {
	out := make([]pb.ExtKeyUsage, 0, len(ekus))
	for _, eku := range ekus {
		if v, ok := extKeyUsageMap[eku]; ok {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Named curves
// ---------------------------------------------------------------------------

func convertNamedCurve(c elliptic.Curve) pb.NamedCurve {
	if c == nil {
		return pb.NamedCurve_NAMED_CURVE_UNSPECIFIED
	}
	switch c {
	case elliptic.P224():
		return pb.NamedCurve_NAMED_CURVE_P224
	case elliptic.P256():
		return pb.NamedCurve_NAMED_CURVE_P256
	case elliptic.P384():
		return pb.NamedCurve_NAMED_CURVE_P384
	case elliptic.P521():
		return pb.NamedCurve_NAMED_CURVE_P521
	default:
		return pb.NamedCurve_NAMED_CURVE_UNSPECIFIED
	}
}

func convertECDHCurve(c ecdh.Curve) pb.NamedCurve {
	switch c {
	case ecdh.P256():
		return pb.NamedCurve_NAMED_CURVE_P256
	case ecdh.P384():
		return pb.NamedCurve_NAMED_CURVE_P384
	case ecdh.P521():
		return pb.NamedCurve_NAMED_CURVE_P521
	case ecdh.X25519():
		return pb.NamedCurve_NAMED_CURVE_X25519
	default:
		return pb.NamedCurve_NAMED_CURVE_UNSPECIFIED
	}
}

// ---------------------------------------------------------------------------
// SAN / name constraints / IP helpers
// ---------------------------------------------------------------------------

func convertSANs(cert *x509.Certificate) *pb.SubjectAlternativeNames {
	sans := &pb.SubjectAlternativeNames{
		DnsNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		Uris:           make([]string, 0, len(cert.URIs)),
	}
	for _, ip := range cert.IPAddresses {
		sans.IpAddresses = append(sans.IpAddresses, ip)
	}
	for _, u := range cert.URIs {
		sans.Uris = append(sans.Uris, u.String())
	}
	return sans
}

func convertNameConstraints(cert *x509.Certificate) *pb.NameConstraints {
	nc := &pb.NameConstraints{
		Critical:                cert.PermittedDNSDomainsCritical,
		PermittedDnsDomains:     cert.PermittedDNSDomains,
		ExcludedDnsDomains:      cert.ExcludedDNSDomains,
		PermittedEmailAddresses: cert.PermittedEmailAddresses,
		ExcludedEmailAddresses:  cert.ExcludedEmailAddresses,
		PermittedUriDomains:     cert.PermittedURIDomains,
		ExcludedUriDomains:      cert.ExcludedURIDomains,
	}
	for _, n := range cert.PermittedIPRanges {
		nc.PermittedIpRanges = append(nc.PermittedIpRanges, convertIPNet(n))
	}
	for _, n := range cert.ExcludedIPRanges {
		nc.ExcludedIpRanges = append(nc.ExcludedIpRanges, convertIPNet(n))
	}
	return nc
}

func convertIPNet(n *net.IPNet) *pb.IPNetwork {
	return &pb.IPNetwork{
		Ip:   n.IP,
		Mask: n.Mask,
	}
}

func convertCRLDistPoints(urls []string) []*pb.DistributionPoint {
	out := make([]*pb.DistributionPoint, 0, len(urls))
	for _, u := range urls {
		out = append(out, &pb.DistributionPoint{
			FullName: []*pb.GeneralName{{Name: &pb.GeneralName_Uri{Uri: u}}},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Public / private key conversion (any Go key → proto wrapper)
// ---------------------------------------------------------------------------

func convertPublicKey(pub any) *pb.PublicKey {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return &pb.PublicKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_RSA,
			Key: &pb.PublicKey_Rsa{Rsa: &pb.RSAPublicKey{
				N:           convertBigInt(k.N),
				E:           int32(k.E),
				KeySizeBits: int32(k.N.BitLen()),
			}},
		}
	case *ecdsa.PublicKey:
		return &pb.PublicKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ECDSA,
			Key: &pb.PublicKey_Ecdsa{Ecdsa: &pb.ECDSAPublicKey{
				Curve:       convertNamedCurve(k.Curve),
				X:           convertBigInt(k.X),
				Y:           convertBigInt(k.Y),
				KeySizeBits: int32(k.Curve.Params().BitSize),
			}},
		}
	case ed25519.PublicKey:
		return &pb.PublicKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ED25519,
			Key: &pb.PublicKey_Ed25519{Ed25519: &pb.Ed25519PublicKey{
				KeyData: []byte(k),
			}},
		}
	case *ecdh.PublicKey:
		return &pb.PublicKey{
			Key: &pb.PublicKey_Ecdh{Ecdh: &pb.ECDHPublicKey{
				Curve:   convertECDHCurve(k.Curve()),
				KeyData: k.Bytes(),
			}},
		}
	default:
		return &pb.PublicKey{}
	}
}

func convertPrivateKey(priv any) *pb.PrivateKey {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pk := &pb.PrivateKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_RSA,
			Key: &pb.PrivateKey_Rsa{Rsa: &pb.RSAPrivateKey{
				PublicKey: convertPublicKey(&k.PublicKey).GetRsa(),
				D:         convertBigInt(k.D),
			}},
		}
		rsaKey := pk.GetRsa()
		for _, p := range k.Primes {
			rsaKey.Primes = append(rsaKey.Primes, convertBigInt(p))
		}
		if k.Precomputed.Dp != nil {
			rsaKey.Precomputed = &pb.RSAPrecomputed{
				Dp:   convertBigInt(k.Precomputed.Dp),
				Dq:   convertBigInt(k.Precomputed.Dq),
				Qinv: convertBigInt(k.Precomputed.Qinv),
			}
		}
		return pk
	case *ecdsa.PrivateKey:
		return &pb.PrivateKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ECDSA,
			Key: &pb.PrivateKey_Ecdsa{Ecdsa: &pb.ECDSAPrivateKey{
				PublicKey: convertPublicKey(&k.PublicKey).GetEcdsa(),
				D:         convertBigInt(k.D),
			}},
		}
	case ed25519.PrivateKey:
		return &pb.PrivateKey{
			Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ED25519,
			Key: &pb.PrivateKey_Ed25519{Ed25519: &pb.Ed25519PrivateKey{
				PublicKey: convertPublicKey(k.Public()).GetEd25519(),
				Seed:      k.Seed(),
			}},
		}
	case *ecdh.PrivateKey:
		return &pb.PrivateKey{
			Key: &pb.PrivateKey_Ecdh{Ecdh: &pb.ECDHPrivateKey{
				PublicKey: convertPublicKey(k.PublicKey()).GetEcdh(),
				KeyData:   k.Bytes(),
			}},
		}
	default:
		return &pb.PrivateKey{}
	}
}

// ---------------------------------------------------------------------------
// Encoding detection helper
// ---------------------------------------------------------------------------

func detectEncoding(data []byte) pb.Encoding {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return pb.Encoding_ENCODING_PEM
	}
	if bytes.HasPrefix(trimmed, []byte("ssh-")) || bytes.HasPrefix(trimmed, []byte("ecdsa-sha2-")) {
		return pb.Encoding_ENCODING_OPENSSH
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return pb.Encoding_ENCODING_JSON
	}
	if isPGPArmor(trimmed) {
		return pb.Encoding_ENCODING_PGP_ASCII_ARMOR
	}
	return pb.Encoding_ENCODING_DER
}

func isPGPArmor(data []byte) bool {
	return bytes.HasPrefix(data, []byte("-----BEGIN PGP "))
}

// ---------------------------------------------------------------------------
// Self-signed detection
// ---------------------------------------------------------------------------

func isSelfSigned(cert *x509.Certificate) bool {
	if len(cert.AuthorityKeyId) > 0 && len(cert.SubjectKeyId) > 0 {
		return bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)
	}
	return strings.EqualFold(cert.Issuer.String(), cert.Subject.String())
}
