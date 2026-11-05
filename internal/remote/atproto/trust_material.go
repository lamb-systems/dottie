package atproto

import (
	"bytes"
	"errors"
	"sort"

	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

func TrustMaterialFromVerifiedRead(read ReadResult, anchor [32]byte) (state.VaultCheckpoint, state.AuthenticatedPositionEvidence, error) {
	if read.Revision == nil || anchor == ([32]byte{}) || read.Policy.Vault == nil || len(read.Policy.Vault) != 32 {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, errors.New("verified read is incomplete")
	}
	policy := policyFromRecord(read.Policy)
	control := controlFromRecord(read.Control)
	head := headFromRecord(read.Head)
	policyBytes, err := vault.EncodePolicy(policy)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	controlBytes, err := vault.EncodeControl(control)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	headBytes, err := vault.EncodeHead(head)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	records := read.Revision.Records()
	checkpointRecord, exists := records[RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}]
	if !exists {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, ErrReadRecordMissing
	}
	decoded, err := DecodeRecord(checkpointRecord.Data)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	remoteCheckpoint, ok := decoded.(CheckpointRecord)
	if !ok || len(remoteCheckpoint.Vault) != 32 || len(remoteCheckpoint.Anchor) != 32 || len(remoteCheckpoint.PolicyDigest) != 32 || len(remoteCheckpoint.Signature) != 64 {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, ErrReadRecordType
	}
	checkpoint := vault.Checkpoint{
		Vault: [32]byte(remoteCheckpoint.Vault), SnapshotCID: bytes.Clone(remoteCheckpoint.SnapshotCID),
		EpochSeq: remoteCheckpoint.EpochSeq, PolicyDigest: [32]byte(remoteCheckpoint.PolicyDigest), Anchor: [32]byte(remoteCheckpoint.Anchor),
		ControlCID: bytes.Clone(remoteCheckpoint.ControlCID),
		Signer:     vault.Signer{DeviceID: remoteCheckpoint.SignerDeviceID, KeyID: bytes.Clone(remoteCheckpoint.SignerKeyID)},
	}
	copy(checkpoint.Signature[:], remoteCheckpoint.Signature)
	checkpointBytes, err := vault.EncodeCheckpoint(checkpoint)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	policyDigest, err := vault.ComputePolicyDigest(policyBytes)
	if err != nil {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
	}
	if checkpoint.Vault != policy.Vault || checkpoint.Anchor != anchor || checkpoint.EpochSeq != policy.EpochSeq ||
		checkpoint.PolicyDigest != policyDigest || !bytes.Equal(checkpoint.ControlCID, read.ControlCID) ||
		!bytes.Equal(checkpoint.SnapshotCID, head.SnapshotCID) || read.EpochSeq != policy.EpochSeq ||
		policyDigest != control.PolicyDigest || policyDigest != head.PolicyDigest {
		return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, ErrReadVaultAuthentication
	}
	certificates := make([][]byte, 0, len(policy.Recipients))
	certificateRecords := make([]CertificateRecord, 0, len(policy.Recipients))
	for key, proven := range records {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		record, err := DecodeRecord(proven.Data)
		if err != nil {
			return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
		}
		certificateRecord, ok := record.(CertificateRecord)
		if !ok {
			return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, ErrReadRecordType
		}
		certificateRecords = append(certificateRecords, certificateRecord)
	}
	sort.Slice(certificateRecords, func(i, j int) bool {
		if certificateRecords[i].DeviceID != certificateRecords[j].DeviceID {
			return certificateRecords[i].DeviceID < certificateRecords[j].DeviceID
		}
		return bytes.Compare(certificateRecords[i].KeyID, certificateRecords[j].KeyID) < 0
	})
	for _, certificateRecord := range certificateRecords {
		encoded, err := vault.EncodeCertificate(certificateFromRecord(certificateRecord))
		if err != nil {
			return state.VaultCheckpoint{}, state.AuthenticatedPositionEvidence{}, err
		}
		certificates = append(certificates, encoded)
	}
	vaultID := policy.Vault
	checkpointState := state.VaultCheckpoint{
		Vault: vaultID, Anchor: anchor, ControlCID: bytes.Clone(read.ControlCID), ControlBytes: controlBytes,
		SnapshotCID: bytes.Clone(head.SnapshotCID), Epoch: policy.EpochSeq, PolicyDigest: policyDigest,
	}
	evidence := state.AuthenticatedPositionEvidence{
		Vault: vaultID, Epoch: policy.EpochSeq, PolicyDigest: policyDigest, Policy: policyBytes,
		Control: controlBytes, Head: headBytes, Certificates: certificates, CheckpointPosition: checkpointBytes,
	}
	return checkpointState, evidence, nil
}
