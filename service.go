package sealcheck

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"strings"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

type SealCheck struct {
	Certificate *x509.Certificate
}

type SealProof struct {
	LogValue string   `json:"logValue"`
	RootHash string   `json:"rootHash"`
	Domain   string   `json:"domain"`
	Proof    []string `json:"proof"`
}

func NewSealCheck() *SealCheck {
	return &SealCheck{}
}

type proofMetadata struct {
	rootHashBytes [32]byte
}

func (s *SealCheck) validateProofPure(proof *SealProof) (*proofMetadata, error) {
	currentHash := sha512.Sum512_256([]byte(proof.LogValue))
	var buffer [64]byte
	for _, segB64 := range proof.Proof {
		seg, err := base64.StdEncoding.DecodeString(segB64)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode proof segment")
		}
		if len(seg) != 33 {
			return nil, errors.New("proof segment is not 33 bytes")
		}
		if seg[0] == 0 {
			copy(buffer[0:32], currentHash[:])
			copy(buffer[32:64], seg[1:])
			currentHash = sha512.Sum512_256(buffer[:])
		} else {
			copy(buffer[0:32], seg[1:])
			copy(buffer[32:64], currentHash[:])
			currentHash = sha512.Sum512_256(buffer[:])
		}
	}

	expectedHash, err := base64.StdEncoding.DecodeString(proof.RootHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode root hash")
	}

	if !bytes.Equal(currentHash[:], expectedHash) {
		return nil, errors.New("root hash mismatches")
	}
	return &proofMetadata{
		rootHashBytes: currentHash,
	}, nil
}

func (s *SealCheck) ValidateJson(rawProof []byte) error {
	var proof SealProof
	err := json.Unmarshal(rawProof, &proof)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal proof")
	}

	metadata, err := s.validateProofPure(&proof)
	if err != nil {
		return errors.Wrap(err, "failed to validate proof")
	}

	domainFirstSegment := strings.SplitN(proof.Domain, ".", 2)[0]
	rootHashInDomain, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(domainFirstSegment))
	if err != nil {
		return errors.Wrap(err, "failed to decode root hash in domain")
	}
	if !bytes.Equal(metadata.rootHashBytes[:], rootHashInDomain) {
		return errors.New("root hash in domain mismatches")
	}

	// binary_parameters=yes:
	// https://www.reddit.com/r/golang/comments/hio7kb/how_to_solve_pq_unnamed_prepared_statement_does/
	crtsh, err := sql.Open("postgres", "postgres://guest@crt.sh:5432/certwatch?sslmode=disable&binary_parameters=yes")
	if err != nil {
		return errors.Wrap(err, "failed to open crt.sh database")
	}
	defer crtsh.Close()

	var crtshId int
	var x509Bytes []byte
	err = crtsh.QueryRow(`
SELECT certificate_id, certificate FROM (
	SELECT *
		FROM certificate_and_identities cai
		WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
		AND cai.NAME_VALUE = $1
		AND NOT x509_hasExtension(cai.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE) -- Exclude precertificate
		LIMIT 1000 -- Prevent the optimizer from merging query condtions
	) t ORDER BY certificate_id DESC LIMIT 1;
	`, proof.Domain).Scan(&crtshId, &x509Bytes)
	if err != nil {
		return errors.Wrap(err, "failed to query crt.sh database")
	}

	cert, err := x509.ParseCertificate(x509Bytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse certificate")
	}

	s.Certificate = cert
	return nil
}
