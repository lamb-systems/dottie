package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/ipfs/go-cid"
)

var (
	ErrRecoveryKitLength   = errors.New("recovery kit must decode to exactly 32 bytes")
	ErrRecoveryKitEncoding = errors.New("recovery kit encoding is invalid")
)

func GenerateRecoveryKit() ([]byte, error) {
	kit := make([]byte, 32)
	if _, err := rand.Read(kit); err != nil {
		return nil, fmt.Errorf("generate recovery kit: %w", err)
	}
	return kit, nil
}

func ParseRecoveryKit(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return nil, ErrRecoveryKitEncoding
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(compact))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecoveryKitEncoding, err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrRecoveryKitLength, len(decoded))
	}
	return decoded, nil
}

func RenderRecoveryKit(kit []byte) (string, error) {
	if len(kit) != 32 {
		return "", fmt.Errorf("%w: got %d bytes", ErrRecoveryKitLength, len(kit))
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(kit)
	var grouped strings.Builder
	grouped.Grow(len(encoded) + len(encoded)/4)
	for offset := 0; offset < len(encoded); offset += 4 {
		if offset > 0 {
			grouped.WriteByte('-')
		}
		end := offset + 4
		if end > len(encoded) {
			end = len(encoded)
		}
		grouped.WriteString(encoded[offset:end])
	}
	return grouped.String(), nil
}

func RecoveryKitVaultID(kit []byte, vaultName string) ([32]byte, error) {
	if len(kit) != 32 {
		return [32]byte{}, fmt.Errorf("%w: recovery kit", ErrFormat)
	}
	return deriveVaultID(kit, vaultName)
}

func VerifyControlState(context *TrustedContext, request VerificationRequest) (VerificationResult, error) {
	result, err := compareControlCheckpoints(context, request)
	if err != nil {
		return VerificationResult{}, err
	}
	if result.validityPassed {
		result.proof = &verificationProof{outcome: result.Outcome, consentAvailable: result.ConsentAvailable, validityPassed: true}
	}
	return result, nil
}

func RecoveryKitCheckpointAnchor(kit []byte, vaultID [32]byte, checkpointBytes []byte) ([32]byte, error) {
	var anchor [32]byte
	publicKey, err := RecoveryKitSigningPublicKey(kit, vaultID)
	if err != nil {
		return anchor, err
	}
	checkpoint, err := VerifyCheckpoint(checkpointBytes, publicKey)
	if err != nil {
		return anchor, err
	}
	if checkpoint.Vault != vaultID {
		return anchor, fmt.Errorf("%w: checkpoint vault", ErrAuthorization)
	}
	return checkpoint.Anchor, nil
}

func RecoveryKitPublicKeyFingerprint(kit []byte, vaultID [32]byte) ([32]byte, error) {
	publicKey, err := RecoveryKitSigningPublicKey(kit, vaultID)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(publicKey), nil
}

func SignRecoveryKitCheckpoint(kit []byte, vaultID, anchor [32]byte, epoch uint64, policyDigest [32]byte, controlCID, snapshotCID []byte) ([]byte, error) {
	if len(kit) != 32 {
		return nil, fmt.Errorf("%w: recovery kit", ErrFormat)
	}
	if epoch == 0 || epoch > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("%w: administrative checkpoint epoch", ErrTransitionEpoch)
	}
	if vaultID == ([32]byte{}) || anchor == ([32]byte{}) || policyDigest == ([32]byte{}) {
		return nil, fmt.Errorf("%w: administrative checkpoint position", ErrFormat)
	}
	if len(controlCID) == 0 || len(controlCID) > MaxParentBytes || len(snapshotCID) == 0 || len(snapshotCID) > MaxParentBytes {
		return nil, fmt.Errorf("%w: administrative checkpoint CID size", ErrFormat)
	}
	if _, err := cid.Cast(controlCID); err != nil {
		return nil, fmt.Errorf("%w: administrative checkpoint control CID", ErrFormat)
	}
	if _, err := cid.Cast(snapshotCID); err != nil {
		return nil, fmt.Errorf("%w: administrative checkpoint snapshot CID", ErrFormat)
	}
	key, err := deriveKitSigningKey(kit, vaultID)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	fingerprint := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return signCheckpoint(Checkpoint{
		Vault: vaultID, Anchor: anchor, EpochSeq: epoch, PolicyDigest: policyDigest,
		ControlCID: bytes.Clone(controlCID), SnapshotCID: bytes.Clone(snapshotCID),
		Signer: Signer{DeviceID: "recovery-kit", KeyID: fingerprint[:]},
	}, key)
}
