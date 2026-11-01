package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const maxAccountVerifyBundleBytes = 4 << 20

type accountControlEvidenceJSON struct {
	Control      string   `json:"control"`
	Policy       string   `json:"policy"`
	Certificates []string `json:"certificates"`
}

type accountVerifyBundleJSON struct {
	Vault         string                       `json:"vault"`
	TrustAnchor   string                       `json:"trust_anchor"`
	Held          *accountControlEvidenceJSON  `json:"held,omitempty"`
	Supplied      accountControlEvidenceJSON   `json:"supplied"`
	Intermediates []accountControlEvidenceJSON `json:"intermediates,omitempty"`
}

func runAccountRecovery(command *urfave.Command) error {
	if command.NArg() != 0 || command.String("vault-name") == "" {
		return usageExit("account recovery requires --vault-name and takes no positional arguments")
	}
	kitInput, err := io.ReadAll(io.LimitReader(command.Reader, 513))
	if err != nil {
		return urfave.Exit("cannot read recovery kit from stdin", 1)
	}
	if len(kitInput) > 512 {
		return urfave.Exit("recovery kit input is too long", 1)
	}
	kit, err := vault.ParseRecoveryKit(string(kitInput))
	if err != nil {
		if errors.Is(err, vault.ErrRecoveryKitLength) {
			return urfave.Exit("recovery kit must decode to exactly 32 bytes", 1)
		}
		return urfave.Exit("recovery kit encoding is invalid", 1)
	}
	vaultID, err := vault.RecoveryKitVaultID(kit, command.String("vault-name"))
	if err != nil {
		return urfave.Exit("cannot derive vault identifier", 1)
	}
	rendered, err := vault.RenderRecoveryKit(kit)
	if err != nil {
		return urfave.Exit("cannot render recovery kit", 1)
	}
	publicKey, err := vault.RecoveryKitSigningPublicKey(kit, vaultID)
	if err != nil {
		return urfave.Exit("cannot derive recovery kit public key", 1)
	}
	publicFingerprint := sha256.Sum256(publicKey)
	anchorLine := "anchor fingerprint: unavailable (no checkpoint supplied)\n"
	if command.String("checkpoint") != "" {
		checkpoint, err := readAccountFile(command.String("checkpoint"), 64<<10)
		if err != nil {
			return urfave.Exit("cannot read checkpoint file", 1)
		}
		anchor, err := vault.RecoveryKitCheckpointAnchor(kit, vaultID, checkpoint)
		if err != nil {
			return urfave.Exit("checkpoint does not verify for this kit and vault", 1)
		}
		anchorLine = fmt.Sprintf("anchor fingerprint: %x\n", anchor)
	}
	output := fmt.Sprintf("recovery kit (keep offline): %s\nvault fingerprint: %x\n%srecovery kit public-key fingerprint: %x\n", rendered, vaultID, anchorLine, publicFingerprint)
	return writeCommandOutput(command, output)
}

func runAccountVerify(ctx context.Context, command *urfave.Command) error {
	if command.NArg() != 0 || command.String("bundle") == "" {
		return usageExit("account verify requires --bundle and takes no positional arguments")
	}
	bundleBytes, err := readAccountFile(command.String("bundle"), maxAccountVerifyBundleBytes)
	if err != nil {
		return urfave.Exit("cannot read verification bundle", 1)
	}
	bundle, err := decodeAccountVerifyBundle(bundleBytes)
	if err != nil {
		return urfave.Exit(err.Error(), 1)
	}
	vaultID, err := parseVaultFingerprint(bundle.Vault)
	if err != nil {
		return usageExit("bundle vault must be a 32-byte hexadecimal identifier")
	}
	trustAnchor, err := parseVaultFingerprint(bundle.TrustAnchor)
	if err != nil {
		return usageExit("bundle trust_anchor must be a 32-byte hexadecimal fingerprint")
	}
	supplied, err := decodeAccountControlEvidence(bundle.Supplied)
	if err != nil {
		return urfave.Exit("invalid supplied control evidence", 1)
	}
	intermediates := make([]vault.ControlEvidence, 0, len(bundle.Intermediates))
	for _, encoded := range bundle.Intermediates {
		evidence, err := decodeAccountControlEvidence(encoded)
		if err != nil {
			return urfave.Exit("invalid intermediate control evidence", 1)
		}
		intermediates = append(intermediates, evidence)
	}
	paths, err := platform.Resolve(os.Getenv)
	if err != nil {
		return urfave.Exit("cannot resolve local state directory", 1)
	}
	store, err := state.Open(paths)
	if err != nil {
		return urfave.Exit("cannot open local checkpoint state", 1)
	}
	defer store.Close()
	var held *vault.HeldCheckpoint
	stored, err := store.VaultCheckpoint(ctx, vaultID)
	if err == nil {
		if bundle.Held == nil {
			return urfave.Exit("bundle held policy and certificates are required for the local checkpoint", 1)
		}
		heldEvidence, evidenceErr := decodeAccountControlEvidence(*bundle.Held)
		if evidenceErr != nil {
			return urfave.Exit("invalid held checkpoint evidence", 1)
		}
		heldBytes, decodeErr := hex.DecodeString(bundle.Held.Control)
		if decodeErr != nil || !bytes.Equal(heldBytes, stored.ControlBytes) || stored.Anchor != trustAnchor {
			return urfave.Exit("bundle held control or anchor does not match local checkpoint state", 1)
		}
		held = &vault.HeldCheckpoint{
			Position: vault.CheckpointPosition{
				Vault: stored.Vault, Anchor: stored.Anchor, ControlCID: stored.ControlCID,
				ControlBytes: stored.ControlBytes, SnapshotCID: stored.SnapshotCID, EpochSeq: stored.Epoch,
				PolicyDigest: stored.PolicyDigest, RecordedAt: stored.RecordedAt,
			},
			Evidence: heldEvidence,
		}
	} else if !errors.Is(err, state.ErrVaultCheckpointNotFound) {
		return urfave.Exit("cannot load local checkpoint state", 1)
	} else if bundle.Held != nil {
		return urfave.Exit("bundle includes held evidence but no local checkpoint is held", 1)
	}

	result, err := vault.VerifyControlState(vault.VerificationRequest{
		Vault: vaultID, TrustAnchor: trustAnchor, Held: held, Supplied: supplied, Intermediates: intermediates,
	})
	if err != nil {
		return urfave.Exit(formatAccountVerificationRefusal(err), 1)
	}
	if command.Bool("consent") {
		result, err = vault.AcceptUnverifiableConsent(result)
		if err != nil {
			if errors.Is(err, vault.ErrConsentNotOffered) {
				return writeVerificationThenFail(command, result, "--consent is accepted only for unverifiable state")
			}
			return urfave.Exit("cannot record unverifiable-state consent", 1)
		}
	} else if result.Outcome == vault.CheckpointUnverifiable {
		if err := writeVerificationReport(command, result); err != nil {
			return err
		}
		return urfave.Exit("freshness is unverifiable; inspection/export-only continuation requires --consent; no data is applied", 1)
	}
	if err := writeVerificationReport(command, result); err != nil {
		return err
	}
	if command.Bool("record") {
		if result.Outcome != vault.CheckpointCurrent && result.Outcome != vault.CheckpointDescendant {
			return urfave.Exit("--record is allowed only after current or descendant verification", 1)
		}
		control, err := vault.DecodeControl(supplied.Control)
		if err != nil {
			return urfave.Exit("verified control could not be decoded for local recording", 1)
		}
		policyDigest, err := vault.ComputePolicyDigest(supplied.Policy)
		if err != nil {
			return urfave.Exit("verified policy could not be decoded for local recording", 1)
		}
		if err := store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
			Vault: vaultID, Anchor: trustAnchor, ControlCID: result.NewerControlCID, ControlBytes: supplied.Control,
			SnapshotCID: control.HeadSnapshotCID, Epoch: control.EpochSeq, PolicyDigest: policyDigest, RecordedAt: time.Now().Unix(),
		}); err != nil {
			if errors.Is(err, state.ErrCheckpointBackwards) {
				return urfave.Exit("local checkpoint update would move backwards", 1)
			}
			return urfave.Exit("cannot record local checkpoint", 1)
		}
		if err := writeCommandOutput(command, "local checkpoint recorded\n"); err != nil {
			return err
		}
	}
	if result.ConsentRecorded {
		return writeCommandOutput(command, "consent recorded for this verification; no data was applied and the checkpoint was not advanced\n")
	}
	return nil
}

func decodeAccountVerifyBundle(encoded []byte) (accountVerifyBundleJSON, error) {
	var bundle accountVerifyBundleJSON
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return accountVerifyBundleJSON{}, errors.New("verification bundle is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return accountVerifyBundleJSON{}, errors.New("verification bundle has trailing data")
	}
	if bundle.Vault == "" || bundle.TrustAnchor == "" || bundle.Supplied.Control == "" || bundle.Supplied.Policy == "" {
		return accountVerifyBundleJSON{}, errors.New("verification bundle is missing required fields")
	}
	if len(bundle.Intermediates) > vault.MaxCheckpointWalkDepth*2 {
		return accountVerifyBundleJSON{}, errors.New("verification bundle has too many intermediates")
	}
	return bundle, nil
}

func decodeAccountControlEvidence(encoded accountControlEvidenceJSON) (vault.ControlEvidence, error) {
	control, err := hex.DecodeString(encoded.Control)
	if err != nil || len(control) == 0 {
		return vault.ControlEvidence{}, errors.New("invalid control bytes")
	}
	policy, err := hex.DecodeString(encoded.Policy)
	if err != nil || len(policy) == 0 {
		return vault.ControlEvidence{}, errors.New("invalid policy bytes")
	}
	if len(encoded.Certificates) == 0 || len(encoded.Certificates) > 64 {
		return vault.ControlEvidence{}, errors.New("invalid certificate set")
	}
	certificates := make([][]byte, 0, len(encoded.Certificates))
	for _, item := range encoded.Certificates {
		certificate, err := hex.DecodeString(item)
		if err != nil || len(certificate) == 0 {
			return vault.ControlEvidence{}, errors.New("invalid certificate bytes")
		}
		certificates = append(certificates, certificate)
	}
	return vault.ControlEvidence{Control: control, Policy: policy, Certificates: certificates}, nil
}

func readAccountFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > maximum {
		return nil, errors.New("local input exceeds size limit")
	}
	return encoded, nil
}

func writeVerificationReport(command *urfave.Command, result vault.VerificationResult) error {
	var output strings.Builder
	fmt.Fprintf(&output, "outcome: %s\nreason code: %s\nreason: %s\n", result.Outcome, result.ReasonCode, escapeField(result.Reason))
	if len(result.NewerControlCID) > 0 {
		fmt.Fprintf(&output, "newer control CID: %x\n", result.NewerControlCID)
	} else {
		output.WriteString("newer control CID: unknown\n")
	}
	if len(result.NeededControlCID) > 0 {
		fmt.Fprintf(&output, "required local control CID: %x\n", result.NeededControlCID)
	}
	fmt.Fprintf(&output, "freshness: %s\n", freshnessSentence(result.Outcome))
	if result.Outcome == vault.CheckpointUnverifiable {
		output.WriteString("consequence: freshness is not established; continuation is inspection/export-only, with no apply\n")
	}
	if result.ConsentRecorded {
		output.WriteString("consent: recorded for this verification only\n")
	}
	return writeCommandOutput(command, output.String())
}

func freshnessSentence(outcome vault.CheckpointOutcome) string {
	switch outcome {
	case vault.CheckpointCurrent:
		return "the supplied control matches the held checkpoint"
	case vault.CheckpointDescendant:
		return "the supplied control is an authenticated descendant of the held checkpoint"
	case vault.CheckpointStale:
		return "the supplied control is an authenticated ancestor and is stale"
	case vault.CheckpointConflicting:
		return "both controls authenticate but their histories conflict"
	case vault.CheckpointUnverifiable:
		return "freshness cannot be established from locally held evidence"
	default:
		return "no freshness conclusion is available"
	}
}

func formatAccountVerificationRefusal(err error) string {
	var refusal *vault.VerificationRefusal
	if errors.As(err, &refusal) {
		if refusal.Check != "" && len(refusal.CID) > 0 {
			return fmt.Sprintf("verification refused: %s %s failed at %x", refusal.Side, refusal.Check, refusal.CID)
		}
		if len(refusal.CID) > 0 {
			return fmt.Sprintf("verification refused: %s %s at %x", refusal.Side, refusal.Code, refusal.CID)
		}
		return fmt.Sprintf("verification refused: %s %s", refusal.Side, refusal.Code)
	}
	return "verification refused: invalid local evidence"
}

func writeVerificationThenFail(command *urfave.Command, result vault.VerificationResult, message string) error {
	if err := writeVerificationReport(command, result); err != nil {
		return err
	}
	return urfave.Exit(message, 1)
}
