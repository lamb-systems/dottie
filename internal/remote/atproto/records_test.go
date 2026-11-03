package atproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lexiconDocument struct {
	Lexicon int                          `json:"lexicon"`
	ID      string                       `json:"id"`
	Defs    map[string]lexiconDefinition `json:"defs"`
}

type lexiconDefinition struct {
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Key         string         `json:"key"`
	Record      map[string]any `json:"record"`
}

type recordFixture struct {
	name   string
	record Record
	object []byte
	field  string
	alter  func(Record) Record
}

func TestVaultLexiconsParseNamespaceScopeAndWriteSet(t *testing.T) {
	lexicons := readLexicons(t)
	recordNSIDs := make([]string, 0, len(lexicons))
	for _, lexicon := range lexicons {
		require.Equal(t, 1, lexicon.Lexicon)
		assert.True(t, strings.HasPrefix(lexicon.ID, "systems.lamb.dottie."), "lexicon NSID = %q", lexicon.ID)
		_, nsidErr := syntax.ParseNSID(lexicon.ID)
		require.NoError(t, nsidErr, "lexicon NSID = %q", lexicon.ID)
		recordNSIDs = append(recordNSIDs, lexicon.ID)
	}
	sort.Strings(recordNSIDs)
	assert.Len(t, recordNSIDs, 7)

	metadata := readClientMetadata(t)
	scopes, ok := metadata["scope"].(string)
	require.True(t, ok)
	repoScopes := make([]string, 0)
	for _, scope := range strings.Fields(scopes) {
		if strings.HasPrefix(scope, "repo:") {
			repoScopes = append(repoScopes, strings.TrimPrefix(scope, "repo:"))
		}
	}
	sort.Strings(repoScopes)
	assert.Equal(t, recordNSIDs, repoScopes)
	actualScopes := strings.Fields(scopes)
	expectedScopes := make([]string, 0, len(recordNSIDs)+2)
	for _, nsid := range recordNSIDs {
		expectedScopes = append(expectedScopes, "repo:"+nsid)
	}
	expectedScopes = append(expectedScopes, "atproto", "blob:application/octet-stream")
	sort.Strings(actualScopes)
	sort.Strings(expectedScopes)
	assert.Equal(t, expectedScopes, actualScopes)

	writeSets := [][]string{
		{VaultPolicyNSID, VaultControlNSID, VaultCertificateNSID, VaultCheckpointNSID},
		{VaultPolicyNSID, VaultControlNSID, VaultCertificateNSID, VaultHeadNSID, VaultSnapshotNSID},
		{VaultHeadNSID, VaultSnapshotNSID},
		{VaultPolicyNSID, VaultControlNSID, VaultCertificateNSID, VaultHeadNSID, VaultSnapshotNSID},
		{VaultControlNSID, VaultCheckpointNSID, VaultCertificateNSID},
		{VaultPolicyNSID, VaultControlNSID, VaultCertificateNSID, VaultCheckpointNSID, VaultHeadNSID},
		{VaultAttestationNSID},
	}
	written := make(map[string]struct{})
	for _, writeSet := range writeSets {
		for _, nsid := range writeSet {
			assert.Contains(t, recordNSIDs, nsid)
			written[nsid] = struct{}{}
		}
	}
	writtenNSIDs := make([]string, 0, len(written))
	for nsid := range written {
		writtenNSIDs = append(writtenNSIDs, nsid)
	}
	sort.Strings(writtenNSIDs)
	assert.Equal(t, recordNSIDs, writtenNSIDs)
}

func TestVaultLexiconFieldsStayOutOfLocalAuthority(t *testing.T) {
	for _, lexicon := range readLexicons(t) {
		properties := lexicon.Defs["main"].Record["properties"].(map[string]any)
		walkLexiconProperties(t, properties, lexicon.ID)
	}
}

func TestVaultLexiconBoundsMatchV02Constants(t *testing.T) {
	lexicons := readLexicons(t)
	properties := make(map[string][]map[string]any)
	for _, lexicon := range lexicons {
		collectLexiconProperties(lexicon.Defs["main"].Record["properties"].(map[string]any), properties)
	}
	for _, field := range []string{"parent", "snapshotCid", "blobCid", "headSnapshotCid", "prevHeadCid", "prevControlCid", "controlCid", "revocationRef"} {
		assert.NotEmpty(t, properties[field], "CID field %s must have a bound", field)
		for _, property := range properties[field] {
			assert.Equal(t, vault.MaxParentBytes, int(property["maxLength"].(float64)), "maximum for %s", field)
		}
	}
	for _, field := range []string{"deviceId", "signerDeviceId", "issuer"} {
		assert.NotEmpty(t, properties[field], "device field %s must have a bound", field)
		for _, property := range properties[field] {
			assert.Equal(t, vault.MaxDeviceIDBytes, int(property["maxLength"].(float64)), "maximum for %s", field)
		}
	}
	for _, field := range []string{"keyId", "signerKeyId"} {
		assert.NotEmpty(t, properties[field], "key field %s must have a bound", field)
		for _, property := range properties[field] {
			assert.Equal(t, vault.MaxKeyIDBytes, int(property["maxLength"].(float64)), "maximum for %s", field)
		}
	}
	assert.Len(t, properties["recipients"], 1)
	for _, property := range properties["recipients"] {
		assert.Equal(t, vault.MaxRecipients, int(property["maxLength"].(float64)))
	}
	for _, field := range []string{"epochSeq", "publicationCount", "certEpoch", "policyRetentionFloor", "retentionFloor"} {
		assert.NotEmpty(t, properties[field], "numeric field %s must have a bound", field)
		for _, property := range properties[field] {
			assert.Equal(t, "integer", property["type"], "type for %s", field)
			assert.Equal(t, float64(MaxRecordInteger), property["maximum"], "maximum for %s", field)
		}
	}
	for field, definitions := range properties {
		for _, definition := range definitions {
			if definition["type"] != "integer" {
				continue
			}
			if constant, ok := definition["const"].(float64); ok {
				assert.LessOrEqual(t, constant, float64(MaxRecordInteger), "constant for %s", field)
				continue
			}
			maximum, ok := definition["maximum"].(float64)
			require.True(t, ok, "integer field %s requires an explicit maximum", field)
			assert.LessOrEqual(t, maximum, float64(MaxRecordInteger), "maximum for %s", field)
		}
	}
	for _, lexicon := range lexicons {
		if lexicon.ID == VaultSnapshotNSID {
			blob := properties["blob"][0]
			assert.Equal(t, vault.MaxEnvelopeBytes, int(blob["maxSize"].(float64)))
			continue
		}
		assert.Contains(t, lexicon.Defs["main"].Description, fmt.Sprint(vault.MaxPolicyObjectBytes))
		assert.Contains(t, lexicon.Defs["main"].Description, "inclusive")
	}
}

func TestVaultLexiconClientMetadataSelfReferenceAndReleaseDomain(t *testing.T) {
	metadata := readClientMetadata(t)
	clientID, ok := metadata["client_id"].(string)
	require.True(t, ok)
	cname, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "CNAME"))
	require.NoError(t, err)
	expectedURL := "https://" + strings.TrimSpace(string(cname)) + "/client-metadata.json"
	assert.Equal(t, expectedURL, clientID)

	for _, root := range []string{"lexicons", "docs"} {
		base := filepath.Join("..", "..", "..", root)
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			text := strings.ToLower(string(contents))
			assert.NotContains(t, text, "example.", "release file %s", path)
			assert.NotContains(t, text, "example.invalid", "release file %s", path)
			return nil
		})
		require.NoError(t, err)
	}
}

func TestVaultRecordsRoundTripAndBindToV02Fixtures(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	require.Len(t, fixtures, 7)
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			encoded, err := EncodeRecord(fixture.record)
			require.NoError(t, err)
			decoded, err := DecodeRecord(encoded)
			require.NoError(t, err)
			assert.Equal(t, fixture.record.LexiconID(), decoded.LexiconID())
			roundTrip, err := EncodeRecord(decoded)
			require.NoError(t, err)
			assert.Equal(t, encoded, roundTrip)
			assert.NoError(t, VerifyRecordBinding(encoded, fixture.object))

			altered := fixture.alter(fixture.record)
			alteredBytes, err := EncodeRecord(altered)
			require.NoError(t, err)
			bindingErr := VerifyRecordBinding(alteredBytes, fixture.object)
			require.Error(t, bindingErr)
			var typed *RecordBindingError
			require.ErrorAs(t, bindingErr, &typed)
			assert.Equal(t, fixture.field, typed.Field)
		})
	}

	snapshot := fixtures[0].record.(SnapshotRecord)
	envelope, err := vault.DecodeEnvelope(fixtures[0].object)
	require.NoError(t, err)
	publisherKey := fixtureSigningKey(12)
	assert.NoError(t, VerifySnapshotRecordSignature(snapshot, publisherKey.Public().(ed25519.PublicKey)))
	assert.Equal(t, envelope.DeviceID, snapshot.SignerDeviceID)
	assert.Equal(t, envelope.KeyID, snapshot.SignerKeyID)
	snapshot.Signature = bytes.Clone(snapshot.Signature)
	snapshot.Signature[0] ^= 0xff
	assert.ErrorAs(t, VerifySnapshotRecordSignature(snapshot, publisherKey.Public().(ed25519.PublicKey)), new(RecordSignatureError))
}

func TestSnapshotRecordSignaturePreimageGolden(t *testing.T) {
	snapshot := v02RecordFixtures(t)[0].record.(SnapshotRecord)
	preimage, err := SnapshotRecordSigningPreimage(snapshot)
	require.NoError(t, err)
	goldenPath := filepath.Join("testdata", "snapshot-record-preimage.hex")
	if os.Getenv("UPDATE_P01_RECORD_VECTOR") == "1" {
		require.NoError(t, os.WriteFile(goldenPath, []byte(hex.EncodeToString(preimage)+"\n"), 0o600))
	}
	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err)
	assert.Equal(t, string(golden), hex.EncodeToString(preimage)+"\n")
}

func TestSnapshotRecordSignaturePreimageCanonicalMapOrdering(t *testing.T) {
	snapshot := v02RecordFixtures(t)[0].record.(SnapshotRecord)
	preimage, err := SnapshotRecordSigningPreimage(snapshot)
	require.NoError(t, err)
	fields := snapshotRecordMap(snapshot)
	delete(fields, "signature")
	canonical, err := atdata.MarshalCBOR(normalizeRecordMap(fields))
	require.NoError(t, err)
	keys := sortedFieldNames(fields)
	reordered := make(map[string]any, len(fields))
	for index := len(keys) - 1; index >= 0; index-- {
		reordered[keys[index]] = fields[keys[index]]
	}
	reorderedBytes, err := atdata.MarshalCBOR(normalizeRecordMap(reordered))
	require.NoError(t, err)
	assert.Equal(t, canonical, reorderedBytes)
	expectedPreimage := append([]byte(RecordSignatureContext), canonical...)
	assert.Equal(t, expectedPreimage, preimage)
}

func TestVaultRecordEncoderAcceptsSafeIntegerBoundary(t *testing.T) {
	for _, fixture := range v02RecordFixtures(t) {
		var altered Record
		switch value := fixture.record.(type) {
		case SnapshotRecord:
			value.EpochSeq = MaxRecordInteger
			altered = value
		case HeadRecord:
			value.EpochSeq = MaxRecordInteger
			value.PublicationCount = MaxRecordInteger
			altered = value
		case ControlRecord:
			value.EpochSeq = MaxRecordInteger
			for index := range value.Revoked {
				value.Revoked[index].CertEpoch = MaxRecordInteger
			}
			altered = value
		case PolicyRecord:
			value.EpochSeq = MaxRecordInteger
			value.PolicyRetentionFloor = MaxRecordInteger
			altered = value
		case CertificateRecord:
			value.CertEpoch = MaxRecordInteger
			altered = value
		case CheckpointRecord:
			value.EpochSeq = MaxRecordInteger
			altered = value
		case AttestationRecord:
			value.RetentionFloor = MaxRecordInteger
			altered = value
		}
		encoded, err := EncodeRecord(altered)
		require.NoError(t, err, "%s at safe integer boundary", fixture.name)
		decoded, err := DecodeRecord(encoded)
		require.NoError(t, err)
		roundTrip, err := EncodeRecord(decoded)
		require.NoError(t, err)
		assert.Equal(t, encoded, roundTrip)
		assert.Equal(t, altered.LexiconID(), decoded.LexiconID())
	}
}

func TestVaultRecordEncoderRejectsIntegersAboveSafeRange(t *testing.T) {
	for _, fixture := range v02RecordFixtures(t) {
		altered := fixture.record
		field := ""
		switch value := fixture.record.(type) {
		case SnapshotRecord:
			value.EpochSeq = MaxRecordInteger + 1
			altered, field = value, "epochSeq"
		case HeadRecord:
			value.PublicationCount = MaxRecordInteger + 1
			altered, field = value, "publicationCount"
		case ControlRecord:
			value.EpochSeq = MaxRecordInteger + 1
			altered, field = value, "epochSeq"
		case PolicyRecord:
			value.PolicyRetentionFloor = MaxRecordInteger + 1
			altered, field = value, "policyRetentionFloor"
		case CertificateRecord:
			value.CertEpoch = MaxRecordInteger + 1
			altered, field = value, "certEpoch"
		case CheckpointRecord:
			value.EpochSeq = MaxRecordInteger + 1
			altered, field = value, "epochSeq"
		case AttestationRecord:
			value.RetentionFloor = MaxRecordInteger + 1
			altered, field = value, "retentionFloor"
		}
		_, err := EncodeRecord(altered)
		require.Error(t, err, "%s must reject an unsafe integer", fixture.name)
		var typed *RecordDecodeError
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, field, typed.Field)
	}

	control := v02RecordFixtures(t)[2].record.(ControlRecord)
	control.Revoked[0].CertEpoch = MaxRecordInteger + 1
	_, err := EncodeRecord(control)
	require.Error(t, err)
	var typed *RecordDecodeError
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "revoked.certEpoch", typed.Field)
}

func TestVaultRecordContextRequiresEntriesAndChecksCrossRecordBindings(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	byType := make(map[string]recordFixture, len(fixtures))
	for _, fixture := range fixtures {
		byType[fixture.record.LexiconID()] = fixture
	}
	policyBytes, err := EncodeRecord(byType[VaultPolicyNSID].record)
	require.NoError(t, err)
	controlBytes, err := EncodeRecord(byType[VaultControlNSID].record)
	require.NoError(t, err)
	publisherCertificateBytes, err := EncodeRecord(byType[VaultCertificateNSID].record)
	require.NoError(t, err)
	rootCertificateObject := readV02Fixture(t, "certificate-root-self-signed.hex")
	rootCertificate, err := vault.DecodeCertificate(rootCertificateObject)
	require.NoError(t, err)
	rootCertificateBytes, err := EncodeRecord(certificateRecordFromObject(rootCertificate))
	require.NoError(t, err)

	for _, fixture := range fixtures {
		t.Run(fixture.name+" missing context", func(t *testing.T) {
			encoded, err := EncodeRecord(fixture.record)
			require.NoError(t, err)
			contextErr := VerifyRecordContext(encoded, RecordContext{})
			require.Error(t, contextErr)
			var typed *RecordContextError
			require.ErrorAs(t, contextErr, &typed)
			assert.NotEmpty(t, typed.Entry)
		})
	}

	snapshotBytes, err := EncodeRecord(byType[VaultSnapshotNSID].record)
	require.NoError(t, err)
	snapshotRecord := byType[VaultSnapshotNSID].record.(SnapshotRecord)
	_, err = recordCID(snapshotBytes)
	require.NoError(t, err)
	blobCID := cid.Cid(snapshotRecord.Blob.Ref).Bytes()

	head := byType[VaultHeadNSID].record.(HeadRecord)
	head.SnapshotCID = bytes.Clone(blobCID)
	head.BlobCID = bytes.Clone(blobCID)
	headBytes, err := EncodeRecord(head)
	require.NoError(t, err)
	headdigest, err := policyDigest(byType[VaultPolicyNSID].record.(PolicyRecord))
	require.NoError(t, err)
	policy := byType[VaultPolicyNSID].record.(PolicyRecord)
	policyDigestBytes := head.PolicyDigest
	assert.Equal(t, headdigest[:], policyDigestBytes)
	assert.NoError(t, VerifyRecordContext(headBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes}))

	control := byType[VaultControlNSID].record.(ControlRecord)
	control.HeadSnapshotCID = bytes.Clone(blobCID)
	controlBytes, err = EncodeRecord(control)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(controlBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes}))
	assert.NoError(t, VerifyRecordContext(snapshotBytes, RecordContext{Policy: policyBytes, Certificate: publisherCertificateBytes}))

	policyBytes, err = EncodeRecord(policy)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(policyBytes, RecordContext{Certificate: rootCertificateBytes}))

	certificateBytes, err := EncodeRecord(byType[VaultCertificateNSID].record)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(certificateBytes, RecordContext{Policy: policyBytes, Control: controlBytes}))

	controlCID, err := recordCID(controlBytes)
	require.NoError(t, err)
	checkpoint := byType[VaultCheckpointNSID].record.(CheckpointRecord)
	checkpoint.ControlCID = controlCID
	checkpoint.SnapshotCID = bytes.Clone(control.HeadSnapshotCID)
	checkpointBytes, err := EncodeRecord(checkpoint)
	require.NoError(t, err)
	trustAnchor := [32]byte(checkpoint.Anchor)
	assert.NoError(t, VerifyRecordContext(checkpointBytes, RecordContext{Policy: policyBytes, Control: controlBytes, TrustAnchor: trustAnchor}))
	contextErr := VerifyRecordContext(checkpointBytes, RecordContext{Policy: policyBytes, Control: controlBytes})
	require.Error(t, contextErr)
	var trustErr *RecordContextError
	require.ErrorAs(t, contextErr, &trustErr)
	assert.Equal(t, "TrustAnchor", trustErr.Entry)

	attestation := byType[VaultAttestationNSID].record.(AttestationRecord)
	controlObject, err := vault.EncodeControl(controlFromRecord(control))
	require.NoError(t, err)
	attestation.ControlCID, err = rawBlobCID(controlObject)
	require.NoError(t, err)
	attestationBytes, err := EncodeRecord(attestation)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(attestationBytes, RecordContext{Policy: policyBytes, Control: controlBytes}))
	attestation.RetentionFloor = policy.PolicyRetentionFloor - 1
	attestationBytes, err = EncodeRecord(attestation)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(attestationBytes, RecordContext{Policy: policyBytes, Control: controlBytes}),
		"record context leaves a below-policy-floor declaration for the attestation judgement to surface")

	previousPolicy := policy
	previousPolicy.EpochSeq = 6
	previousPolicy.PrevPolicyDigest = make([]byte, 32)
	previousBytes, err := EncodeRecord(previousPolicy)
	require.NoError(t, err)
	previousDigest, err := policyDigest(previousPolicy)
	require.NoError(t, err)
	nextPolicy := policy
	nextPolicy.EpochSeq = 8
	nextPolicy.PrevPolicyDigest = bytes.Clone(previousDigest[:])
	nextBytes, err := EncodeRecord(nextPolicy)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(nextBytes, RecordContext{Certificate: rootCertificateBytes, PreviousPolicy: previousBytes}))
	contextErr = VerifyRecordContext(nextBytes, RecordContext{Certificate: rootCertificateBytes})
	require.Error(t, contextErr)
	var typed *RecordContextError
	require.ErrorAs(t, contextErr, &typed)
	assert.Equal(t, "PreviousPolicy", typed.Entry)
}

func TestVaultCertificateContextKeepsSigningAndWrappingKeyIDsSeparate(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	byType := make(map[string]recordFixture, len(fixtures))
	for _, fixture := range fixtures {
		byType[fixture.record.LexiconID()] = fixture
	}
	policyBytes, err := EncodeRecord(byType[VaultPolicyNSID].record)
	require.NoError(t, err)
	controlBytes, err := EncodeRecord(byType[VaultControlNSID].record)
	require.NoError(t, err)
	certificate := byType[VaultCertificateNSID].record.(CertificateRecord)
	assert.NotEqual(t, byType[VaultPolicyNSID].record.(PolicyRecord).Recipients[0].KeyID, certificate.KeyID)
	certificateBytes, err := EncodeRecord(certificate)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(certificateBytes, RecordContext{Policy: policyBytes, Control: controlBytes}))

	certificate.EncryptionPublicKey = bytes.Clone(certificate.EncryptionPublicKey)
	certificate.EncryptionPublicKey[0] ^= 0xff
	certificateBytes, err = EncodeRecord(certificate)
	require.NoError(t, err)
	contextErr := VerifyRecordContext(certificateBytes, RecordContext{Policy: policyBytes, Control: controlBytes})
	require.Error(t, contextErr)
	var typed *RecordContextError
	require.ErrorAs(t, contextErr, &typed)
	assert.Equal(t, "encryptionPublicKey", typed.Field)

	certificate = byType[VaultCertificateNSID].record.(CertificateRecord)
	certificate.DeviceID = "device-not-in-policy"
	certificateBytes, err = EncodeRecord(certificate)
	require.NoError(t, err)
	contextErr = VerifyRecordContext(certificateBytes, RecordContext{Policy: policyBytes, Control: controlBytes})
	require.Error(t, contextErr)
	require.ErrorAs(t, contextErr, &typed)
	assert.Equal(t, "role", typed.Field)
}

func TestVaultRecordDecoderRejectsUnknownFields(t *testing.T) {
	fixture := v02RecordFixtures(t)[1]
	encoded, err := EncodeRecord(fixture.record)
	require.NoError(t, err)
	object, err := atdata.UnmarshalCBOR(encoded)
	require.NoError(t, err)
	object["futureField"] = "must not be discarded"
	withUnknown, err := atdata.MarshalCBOR(object)
	require.NoError(t, err)
	_, err = DecodeRecord(withUnknown)
	require.Error(t, err)
	var typed *RecordDecodeError
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "futureField", typed.Field)
}

func TestVaultRecordGoFieldsMatchLexiconProperties(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	lexicons := readLexicons(t)
	byNSID := make(map[string]lexiconDocument, len(lexicons))
	for _, lexicon := range lexicons {
		byNSID[lexicon.ID] = lexicon
	}
	for _, fixture := range fixtures {
		lexicon := byNSID[fixture.record.LexiconID()]
		properties := lexicon.Defs["main"].Record["properties"].(map[string]any)
		fields := reflect.TypeOf(fixture.record)
		goFields := make([]string, 0, fields.NumField())
		for index := 0; index < fields.NumField(); index++ {
			goFields = append(goFields, strings.Split(fields.Field(index).Tag.Get("json"), ",")[0])
		}
		lexiconFields := make([]string, 0, len(properties))
		for name := range properties {
			lexiconFields = append(lexiconFields, name)
		}
		sort.Strings(goFields)
		sort.Strings(lexiconFields)
		assert.Equal(t, goFields, lexiconFields, "Go fields for %s", fixture.record.LexiconID())
		requiredRaw, ok := lexicon.Defs["main"].Record["required"].([]any)
		require.True(t, ok, "required fields for %s", fixture.record.LexiconID())
		requiredFields := make([]string, len(requiredRaw))
		for index, field := range requiredRaw {
			requiredFields[index], ok = field.(string)
			require.True(t, ok, "required field %d for %s", index, fixture.record.LexiconID())
		}
		sort.Strings(requiredFields)
		assert.Equal(t, lexiconFields, requiredFields, "required fields for %s", fixture.record.LexiconID())
	}
}

func readLexicons(t *testing.T) []lexiconDocument {
	t.Helper()
	directory := filepath.Join("..", "..", "..", "lexicons")
	paths, err := filepath.Glob(filepath.Join(directory, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	lexicons := make([]lexiconDocument, 0, len(paths))
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		var lexicon lexiconDocument
		require.NoError(t, json.Unmarshal(contents, &lexicon), "lexicon %s", path)
		require.Contains(t, lexicon.Defs, "main", "lexicon %s", path)
		require.Equal(t, "record", lexicon.Defs["main"].Type, "lexicon %s", path)
		lexicons = append(lexicons, lexicon)
	}
	return lexicons
}

func readClientMetadata(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "client-metadata.json")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(contents, &metadata))
	return metadata
}

func walkLexiconProperties(t *testing.T, properties map[string]any, nsid string) {
	t.Helper()
	for name, raw := range properties {
		lower := strings.ToLower(name)
		assert.NotContains(t, lower, "path", "%s has local path field %s", nsid, name)
		assert.NotContains(t, lower, "target", "%s has local target field %s", nsid, name)
		assert.NotContains(t, lower, "mode", "%s has local mode field %s", nsid, name)
		definition, ok := raw.(map[string]any)
		require.True(t, ok, "%s.%s property must be an object", nsid, name)
		if nested, ok := definition["properties"].(map[string]any); ok {
			walkLexiconProperties(t, nested, nsid)
		}
		if items, ok := definition["items"].(map[string]any); ok {
			if nested, ok := items["properties"].(map[string]any); ok {
				walkLexiconProperties(t, nested, nsid)
			}
		}
	}
}

func collectLexiconProperties(properties map[string]any, collected map[string][]map[string]any) {
	for name, raw := range properties {
		definition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		collected[name] = append(collected[name], definition)
		if nested, ok := definition["properties"].(map[string]any); ok {
			collectLexiconProperties(nested, collected)
		}
		if items, ok := definition["items"].(map[string]any); ok {
			if nested, ok := items["properties"].(map[string]any); ok {
				collectLexiconProperties(nested, collected)
			}
		}
	}
}

func readV02Fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "vault", "testdata", name)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	decoded, err := hex.DecodeString(strings.TrimSpace(string(contents)))
	require.NoError(t, err)
	return decoded
}

func v02RecordFixtures(t *testing.T) []recordFixture {
	t.Helper()
	envelopeBytes := readV02Fixture(t, "envelope-one-recipient-chain.hex")
	envelope, err := vault.DecodeEnvelope(envelopeBytes)
	require.NoError(t, err)
	blobCID, err := rawBlobCID(envelopeBytes)
	require.NoError(t, err)
	parsedBlobCID, err := cid.Cast(blobCID)
	require.NoError(t, err)
	digest := sha256.Sum256(envelope.Signature[:])
	snapshot := SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob:           atdata.Blob{Ref: atdata.CIDLink(parsedBlobCID), MimeType: "application/octet-stream", Size: int64(len(envelopeBytes))},
		SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID), EnvelopeSignatureDigest: bytes.Clone(digest[:]),
	}
	snapshot, err = SignSnapshotRecord(snapshot, fixtureSigningKey(12))
	require.NoError(t, err)

	headObjectBytes := readV02Fixture(t, "head-publisher-signed-chain.hex")
	headObject, err := vault.DecodeHead(headObjectBytes)
	require.NoError(t, err)
	controlObjectBytes := readV02Fixture(t, "control-root-signed-chain.hex")
	controlObject, err := vault.DecodeControl(controlObjectBytes)
	require.NoError(t, err)
	policyObjectBytes := readV02Fixture(t, "policy-root-signed-chain.hex")
	policyObject, err := vault.DecodePolicy(policyObjectBytes)
	require.NoError(t, err)
	certificateObjectBytes := readV02Fixture(t, "certificate-publisher-root-issued-chain.hex")
	certificateObject, err := vault.DecodeCertificate(certificateObjectBytes)
	require.NoError(t, err)
	checkpointObjectBytes := readV02Fixture(t, "checkpoint-root-signed-chain.hex")
	checkpointObject, err := vault.DecodeCheckpoint(checkpointObjectBytes)
	require.NoError(t, err)
	attestationObjectBytes := readV02Fixture(t, "attestation-root-signed-chain.hex")
	attestationObject, err := vault.DecodeAttestation(attestationObjectBytes)
	require.NoError(t, err)

	return []recordFixture{
		{name: "snapshot", record: snapshot, object: envelopeBytes, field: "policyDigest", alter: func(record Record) Record {
			value := record.(SnapshotRecord)
			value.PolicyDigest = bytes.Clone(value.PolicyDigest)
			value.PolicyDigest[0] ^= 0xff
			return value
		}},
		{name: "head", record: headRecordFromObject(headObject), object: headObjectBytes, field: "publicationCount", alter: func(record Record) Record {
			value := record.(HeadRecord)
			value.PublicationCount++
			return value
		}},
		{name: "control", record: controlRecordFromObject(controlObject), object: controlObjectBytes, field: "epochSeq", alter: func(record Record) Record {
			value := record.(ControlRecord)
			value.EpochSeq++
			return value
		}},
		{name: "policy", record: policyRecordFromObject(policyObject), object: policyObjectBytes, field: "prevPolicyDigest", alter: func(record Record) Record {
			value := record.(PolicyRecord)
			value.PrevPolicyDigest = bytes.Clone(value.PrevPolicyDigest)
			value.PrevPolicyDigest[0] ^= 0xff
			return value
		}},
		{name: "certificate", record: certificateRecordFromObject(certificateObject), object: certificateObjectBytes, field: "signingPublicKey", alter: func(record Record) Record {
			value := record.(CertificateRecord)
			value.SigningPublicKey = bytes.Clone(value.SigningPublicKey)
			value.SigningPublicKey[0] ^= 0xff
			return value
		}},
		{name: "checkpoint", record: checkpointRecordFromObject(checkpointObject), object: checkpointObjectBytes, field: "anchor", alter: func(record Record) Record {
			value := record.(CheckpointRecord)
			value.Anchor = bytes.Clone(value.Anchor)
			value.Anchor[0] ^= 0xff
			return value
		}},
		{name: "attestation", record: attestationRecordFromObject(attestationObject), object: attestationObjectBytes, field: "retentionFloor", alter: func(record Record) Record {
			value := record.(AttestationRecord)
			value.RetentionFloor++
			return value
		}},
	}
}

func headRecordFromObject(value vault.Head) HeadRecord {
	return HeadRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, PolicyDigest: bytes.Clone(value.PolicyDigest[:]),
		SnapshotCID: bytes.Clone(value.SnapshotCID), BlobCID: bytes.Clone(value.BlobCID), PublicationCount: value.PublicationCount,
		PrevHeadCID: bytes.Clone(value.PrevHeadCID), SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID),
		Signature: bytes.Clone(value.Signature[:]),
	}
}

func controlRecordFromObject(value vault.Control) ControlRecord {
	revoked := make([]RevokedDeviceRecord, len(value.Revoked))
	for index, entry := range value.Revoked {
		revoked[index] = RevokedDeviceRecord{DeviceID: entry.DeviceID, CertEpoch: entry.CertEpoch}
	}
	return ControlRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, PolicyDigest: bytes.Clone(value.PolicyDigest[:]),
		HeadSnapshotCID: bytes.Clone(value.HeadSnapshotCID), Revoked: revoked, PrevControlCID: bytes.Clone(value.PrevControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func policyRecordFromObject(value vault.Policy) PolicyRecord {
	roles := make([]PolicyRoleRecord, len(value.Roles))
	for index, entry := range value.Roles {
		roles[index] = PolicyRoleRecord{DeviceID: entry.DeviceID, Role: uint8(entry.Role)}
	}
	recipients := make([]PolicyRecipientRecord, len(value.Recipients))
	for index, entry := range value.Recipients {
		recipients[index] = PolicyRecipientRecord{DeviceID: entry.DeviceID, KeyID: bytes.Clone(entry.KeyID), PublicKey: bytes.Clone(entry.PublicKey[:])}
	}
	return PolicyRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), EpochSeq: value.EpochSeq, Roles: roles, Recipients: recipients,
		PolicyRetentionFloor: value.PolicyRetentionFloor, RetainedRecoveryPoints: value.RetainedRecoveryPoints,
		MaxPublications: value.MaxPublications, MaxEpochAge: value.MaxEpochAge, RecoveryAnchor: bytes.Clone(value.RecoveryAnchor[:]),
		PrevPolicyDigest: bytes.Clone(value.PrevPolicyDigest[:]), SignerDeviceID: value.Signer.DeviceID,
		SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func certificateRecordFromObject(value vault.Certificate) CertificateRecord {
	return CertificateRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID, KeyID: bytes.Clone(value.KeyID),
		SigningPublicKey: bytes.Clone(value.SigningPublicKey[:]), EncryptionPublicKey: bytes.Clone(value.EncryptionPublicKey[:]),
		Role: uint8(value.Role), CertEpoch: value.CertEpoch, Issuer: value.Issuer, RevocationRef: bytes.Clone(value.RevocationRef),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func checkpointRecordFromObject(value vault.Checkpoint) CheckpointRecord {
	return CheckpointRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), SnapshotCID: bytes.Clone(value.SnapshotCID), EpochSeq: value.EpochSeq,
		PolicyDigest: bytes.Clone(value.PolicyDigest[:]), Anchor: bytes.Clone(value.Anchor[:]), ControlCID: bytes.Clone(value.ControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func attestationRecordFromObject(value vault.Attestation) AttestationRecord {
	return AttestationRecord{
		SchemaVersion: 1, Vault: bytes.Clone(value.Vault[:]), DeviceID: value.DeviceID, PolicyDigest: bytes.Clone(value.PolicyDigest[:]),
		RetentionFloor: value.RetentionFloor, RetainedRecoveryPoints: value.RetainedRecoveryPoints, ControlCID: bytes.Clone(value.ControlCID),
		SignerDeviceID: value.Signer.DeviceID, SignerKeyID: bytes.Clone(value.Signer.KeyID), Signature: bytes.Clone(value.Signature[:]),
	}
}

func fixtureSigningKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func TestSnapshotCidDenotesTheEnvelopeNotTheRecord(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	byType := make(map[string]recordFixture, len(fixtures))
	for _, fixture := range fixtures {
		byType[fixture.record.LexiconID()] = fixture
	}
	snapshotBytes, err := EncodeRecord(byType[VaultSnapshotNSID].record)
	require.NoError(t, err)
	snapshot := byType[VaultSnapshotNSID].record.(SnapshotRecord)
	envelopeCID := cid.Cid(snapshot.Blob.Ref).Bytes()
	recordCIDValue, err := recordCID(snapshotBytes)
	require.NoError(t, err)
	policyBytes, err := EncodeRecord(byType[VaultPolicyNSID].record)
	require.NoError(t, err)

	head := byType[VaultHeadNSID].record.(HeadRecord)
	head.SnapshotCID = bytes.Clone(envelopeCID)
	head.BlobCID = bytes.Clone(envelopeCID)
	headBytes, err := EncodeRecord(head)
	require.NoError(t, err)
	assert.NoError(t, VerifyRecordContext(headBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes}),
		"head.snapshotCid denotes the envelope CID")

	drifted := head
	drifted.SnapshotCID = bytes.Clone(recordCIDValue)
	driftedBytes, err := EncodeRecord(drifted)
	require.NoError(t, err)
	assert.Error(t, VerifyRecordContext(driftedBytes, RecordContext{Policy: policyBytes, Snapshot: snapshotBytes}),
		"the snapshot record CID is a different identifier and must not satisfy the binding")
}

func TestHeadMayAdvanceWithinAnEpochWithoutAControlWrite(t *testing.T) {
	fixtures := v02RecordFixtures(t)
	byType := make(map[string]recordFixture, len(fixtures))
	for _, fixture := range fixtures {
		byType[fixture.record.LexiconID()] = fixture
	}
	snapshotBytes, err := EncodeRecord(byType[VaultSnapshotNSID].record)
	require.NoError(t, err)
	snapshot := byType[VaultSnapshotNSID].record.(SnapshotRecord)
	envelopeCID := cid.Cid(snapshot.Blob.Ref).Bytes()
	policyBytes, err := EncodeRecord(byType[VaultPolicyNSID].record)
	require.NoError(t, err)
	controlBytes, err := EncodeRecord(byType[VaultControlNSID].record)
	require.NoError(t, err)

	advanced := byType[VaultHeadNSID].record.(HeadRecord)
	advanced.SnapshotCID = bytes.Clone(envelopeCID)
	advanced.BlobCID = bytes.Clone(envelopeCID)
	advancedBytes, err := EncodeRecord(advanced)
	require.NoError(t, err)

	control, err := DecodeRecord(controlBytes)
	require.NoError(t, err)
	controlValue := control.(ControlRecord)
	require.NotEqual(t, controlValue.HeadSnapshotCID, advanced.SnapshotCID,
		"this fixture is only meaningful when the head has moved past the epoch's opening snapshot")

	assert.NoError(t, VerifyRecordContext(advancedBytes, RecordContext{
		Policy:   policyBytes,
		Control:  controlBytes,
		Snapshot: snapshotBytes,
	}), "a head advanced within an epoch is coherent with a control that names the epoch's first snapshot")

	assert.NoError(t, VerifyRecordContext(controlBytes, RecordContext{
		Policy:   policyBytes,
		Snapshot: snapshotBytes,
	}), "the control record stays coherent when the supplied snapshot is the advanced head, not the one it names")
}
