package atproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"
)

type publicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopHeader struct {
	Typ string    `json:"typ"`
	Alg string    `json:"alg"`
	JWK publicJWK `json:"jwk"`
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func publicKeyJWK(key *ecdsa.PrivateKey) publicJWK {
	return publicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

func decodePublicJWK(jwk publicJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("unsupported DPoP JWK")
	}
	x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
	y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("invalid DPoP JWK coordinates")
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, errors.New("DPoP JWK is not on P-256")
	}
	return public, nil
}

func makeDPoPProof(key *ecdsa.PrivateKey, method, endpoint string, now time.Time, random io.Reader, accessToken Secret, nonce string) (string, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("DPoP requires a P-256 private key")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("DPoP target must be an HTTPS URL")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if random == nil {
		random = rand.Reader
	}
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, jtiBytes); err != nil {
		return "", errors.New("cannot generate DPoP proof identifier")
	}
	claims := dpopClaims{JTI: base64.RawURLEncoding.EncodeToString(jtiBytes), HTM: strings.ToUpper(method), HTU: parsed.String(), IAT: now.Unix(), Nonce: nonce}
	if len(accessToken.value) > 0 {
		digest := sha256.Sum256(accessToken.value)
		claims.ATH = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	headerJSON, err := json.Marshal(dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: publicKeyJWK(key)})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(random, key, digest[:])
	if err != nil {
		return "", errors.New("cannot sign DPoP proof")
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func marshalPrivateKey(key *ecdsa.PrivateKey) (Secret, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Secret{}, errors.New("cannot encode DPoP private key")
	}
	return NewSecret(base64.RawURLEncoding.EncodeToString(encoded)), nil
}

func parsePrivateKey(secret Secret) (*ecdsa.PrivateKey, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(secret.Reveal())
	if err != nil {
		return nil, errors.New("invalid stored DPoP private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, errors.New("invalid stored DPoP private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D == nil {
		return nil, errors.New("stored DPoP key is not P-256")
	}
	return key, nil
}
