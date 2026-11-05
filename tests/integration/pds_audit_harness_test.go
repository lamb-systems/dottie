package integration

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipld/go-car"
	"github.com/lamb-systems/dottie/internal/cli"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const publicationAuditDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
const publicationAuditDeviceID = "publication-device-public"
const publicationAuditFileTargetID = "publication-private-file-target"
const publicationAuditSettingsTargetID = "publication-private-settings-target"
const publicationAuditCollection = "systems.lamb.dottie.vaultSnapshot"

var publicationAuditCollections = []string{
	atproto.VaultHeadNSID, atproto.VaultControlNSID, atproto.VaultSnapshotNSID,
	atproto.VaultPolicyNSID, atproto.VaultCertificateNSID, atproto.VaultCheckpointNSID,
	atproto.VaultAttestationNSID,
}

func liveArtifactDir(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("DOTTIE_LIVE_ARTIFACT_DIR"); configured != "" {
		require.True(t, filepath.IsAbs(configured), "DOTTIE_LIVE_ARTIFACT_DIR must be an absolute path")
		require.NoError(t, os.MkdirAll(configured, 0o700))
		return configured
	}
	directory, err := os.MkdirTemp("", "dottie-live-audit-")
	require.NoError(t, err)
	return directory
}

type publicationAuditClass string

const (
	publicationConfidential publicationAuditClass = "confidential"
	publicationCredential   publicationAuditClass = "credential"
	publicationPublic       publicationAuditClass = "public-intended"
)

type publicationCanary struct {
	name  string
	class publicationAuditClass
	raw   []byte
	forms [][]byte
}

type publicationCanaries struct {
	items []publicationCanary
}

func (registry *publicationCanaries) add(name string, class publicationAuditClass, raw []byte) {
	forms := [][]byte{bytes.Clone(raw)}
	text := string(raw)
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw),
		hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)),
	} {
		if encoded != "" && encoded != text {
			forms = append(forms, []byte(encoded))
		}
	}
	registry.items = append(registry.items, publicationCanary{name: name, class: class, raw: bytes.Clone(raw), forms: forms})
}

func (registry publicationCanaries) forClass(class publicationAuditClass) []publicationCanary {
	result := make([]publicationCanary, 0)
	for _, item := range registry.items {
		if item.class == class {
			result = append(result, item)
		}
	}
	return result
}

func (registry publicationCanaries) forbidden() []publicationCanary {
	result := make([]publicationCanary, 0)
	for _, item := range registry.items {
		if item.class != publicationPublic {
			result = append(result, item)
		}
	}
	return result
}

type publicationKeyring struct {
	devices map[string]vault.DeviceMaterial
}

func (keyring *publicationKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	device, ok := keyring.devices[deviceID]
	if vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, errors.New("synthetic device key is unavailable")
	}
	if !ok {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return device, nil
}

func (keyring *publicationKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, device vault.DeviceMaterial) error {
	if vaultID == ([32]byte{}) || device.DeviceID == "" {
		return errors.New("invalid synthetic device keys")
	}
	if _, exists := keyring.devices[device.DeviceID]; exists {
		return errors.New("synthetic device keys already exist")
	}
	keyring.devices[device.DeviceID] = device
	return nil
}

func (keyring *publicationKeyring) LoadDeviceKeysForVault(_ context.Context, vaultID [32]byte) ([]vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || len(keyring.devices) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	materials := make([]vault.DeviceMaterial, 0, len(keyring.devices))
	for _, device := range keyring.devices {
		materials = append(materials, device)
	}
	return materials, nil
}

func (keyring *publicationKeyring) DeleteDeviceKeys(_ context.Context, _ [32]byte, deviceID string) error {
	delete(keyring.devices, deviceID)
	return nil
}

type publicationSettings struct {
	settingCanary string
}

func (settings publicationSettings) Resolve(_ context.Context, _ string, _ string, _ string) (string, error) {
	return "/", nil
}

func (settings publicationSettings) Capture(_ context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	if len(refs) == 0 {
		return service.SettingsCapture{}, errors.New("approved appearance settings are empty")
	}
	ref := refs[0]
	entry := model.Entry{TargetID: targetID, Setting: &model.SettingEntry{
		SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key, State: model.SettingPresent,
		Value: &model.VariantValue{Type: "s", Text: "'" + settings.settingCanary + "'"},
	}}
	return service.SettingsCapture{Entries: []model.Entry{entry}}, nil
}

func (publicationSettings) Backend() syncengine.SettingsBackend { return publicationSettingsBackend{} }

type publicationSettingsBackend struct{}

func (publicationSettingsBackend) Observe(context.Context, model.EntryKey) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{}, nil
}

func (publicationSettingsBackend) Canonicalize(_ context.Context, _ model.EntryKey, valueType, text string) (syncengine.SettingValue, error) {
	return syncengine.SettingValue{Present: true, Type: valueType, Text: text, Writable: true}, nil
}

func (publicationSettingsBackend) Set(context.Context, model.EntryKey, string, string) error {
	return nil
}
func (publicationSettingsBackend) Reset(context.Context, model.EntryKey) error { return nil }

type publicationReadSession struct {
	did     string
	methods []atproto.VerificationMethod
}

func (session publicationReadSession) ReadRequest(_ context.Context, selection service.VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{
		DID: session.did, DIDDocumentID: session.did, VerificationMethods: session.methods,
		Vault: selection.Vault, TrustAnchor: anchor, DeviceKeyID: bytes.Clone(device.KeyID), DeviceKey: device.Recipient,
		PreviousPolicy: bytes.Clone(previousPolicy), PreviousControl: bytes.Clone(previousControl),
	}, nil
}

type publicationPublisher struct {
	io atproto.ATProtoPublicationIO
}

func (publisher publicationPublisher) PublicationIO(context.Context, service.VaultSelection, service.TrustMaterial, service.ReadOutcome) (atproto.ATProtoPublicationIO, error) {
	return publisher.io, nil
}

type publicationFixture struct {
	t                  *testing.T
	paths              platform.Paths
	store              *state.Store
	keyring            *publicationKeyring
	settings           publicationSettings
	pds                *atprototest.MemoryPDS
	repoKey            *atcrypto.PrivateKeyP256
	did                string
	blobLimit          int64
	transport          atproto.Transport
	reader             atproto.RevisionReader
	coordinator        *service.Coordinator
	root               vault.DeviceMaterial
	genesis            vault.Genesis
	selection          service.VaultSelection
	kit                []byte
	canaries           publicationCanaries
	filePath           string
	publishedPlaintext []byte
}

func newPublicationFixture(t *testing.T) *publicationFixture {
	t.Helper()
	repoKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, repoKey)
	require.NoError(t, err)
	reader := publicationAuditReader(pds, publicationAuditDID)
	return newPublicationFixtureWithTransport(t, pds, reader, publicationAuditDID, 1<<20, pds, repoKey, nil)
}

func newPublicationFixtureWithTransport(t *testing.T, transport atproto.Transport, reader atproto.RevisionReader, did string, blobLimit int64, pds *atprototest.MemoryPDS, repoKey *atcrypto.PrivateKeyP256, beforeGenesisWrite func(vault.Genesis, vault.DeviceMaterial)) *publicationFixture {
	t.Helper()
	rootDir := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(rootDir, "home"), ConfigHome: filepath.Join(rootDir, "config"),
		StateHome: filepath.Join(rootDir, "state"), CacheHome: filepath.Join(rootDir, "cache"),
		DataHome: filepath.Join(rootDir, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	rootSigning, rootRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	device := vault.DeviceMaterial{DeviceID: publicationAuditDeviceID, KeyID: bytes.Clone(rootSigning.Public().(ed25519.PublicKey)), Signing: rootSigning, Recipient: rootRecipient}
	kitText := []byte("credential-kit-canary-" + hex.EncodeToString(kit))
	fileCanary := []byte("CONFIDENTIAL_FILE_CANARY_6a37b4f1")
	settingCanary := "CONFIDENTIAL_SETTING_CANARY_42d901bc"
	credentialCanary := []byte("eyJ.synthetic.access-token-canary.credential")
	registry := publicationCanaries{}
	registry.add("file-content", publicationConfidential, fileCanary)
	registry.add("relative-path", publicationConfidential, []byte("prefs/private-profile.toml"))
	registry.add("setting-value", publicationConfidential, []byte(settingCanary))
	registry.add("target-id", publicationConfidential, []byte(publicationAuditFileTargetID))
	registry.add("settings-target-id", publicationConfidential, []byte(publicationAuditSettingsTargetID))
	registry.add("recovery-kit", publicationCredential, kit)
	registry.add("recovery-kit-encoded", publicationCredential, kitText)
	registry.add("device-signing-private-key", publicationCredential, rootSigning)
	registry.add("device-recipient-private-key", publicationCredential, rootRecipient.Bytes())
	registry.add("synthetic-oauth-token", publicationCredential, credentialCanary)
	registry.add("home-root", publicationConfidential, []byte(paths.Home))
	registry.add("config-root", publicationConfidential, []byte(paths.ConfigHome))
	registry.add("state-root", publicationConfidential, []byte(paths.StateHome))
	registry.add("cache-root", publicationConfidential, []byte(paths.CacheHome))
	registry.add("data-root", publicationConfidential, []byte(paths.DataHome))
	registry.add("temporary-root", publicationConfidential, []byte(filepath.Dir(paths.Home)))
	registry.add("device-id", publicationPublic, []byte(device.DeviceID))
	fileTarget, settingsTarget := publicationAuditTargets(t, publicationAuditFileTargetID, publicationAuditSettingsTargetID)
	configuration := config.Default()
	configuration.Targets = []config.Target{fileTarget, settingsTarget}
	require.NoError(t, config.Save(paths, configuration))
	for _, target := range configuration.Targets {
		descriptor := state.TargetDescriptor{ID: target.ID, Version: 1, Source: target.Source, SourceVersion: model.SourceVersion, Mode: string(config.Review), CreatedAt: 1}
		if target.Root != nil {
			descriptor.LogicalBase = target.Root.Base
			descriptor.LogicalPath = target.Root.Path
			descriptor.Kind = target.Root.Kind
		}
		require.NoError(t, store.PutTarget(context.Background(), descriptor))
	}
	fileRoot, err := fileTarget.ResolvedPath(paths)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(fileRoot, 0o700))
	filePath := filepath.Join(fileRoot, "prefs", "private-profile.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o700))
	require.NoError(t, os.WriteFile(filePath, fileCanary, 0o600))
	settings := publicationSettings{settingCanary: settingCanary}
	keyring := &publicationKeyring{devices: map[string]vault.DeviceMaterial{device.DeviceID: device}}
	genesis := publicationAuditGenesis(t, kit, device)
	registry.add("vault-id", publicationPublic, []byte(hex.EncodeToString(genesis.Vault[:])))
	if beforeGenesisWrite != nil {
		beforeGenesisWrite(genesis, device)
	}
	ctx := context.Background()
	clock := time.Unix(1_800_000_000, 0)
	reader.Transport = transport
	genesisResult, err := atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: reader, Transport: transport, BlobUploadLimit: blobLimit, DID: did,
		ObservationStore: store, Clock: func() time.Time { return clock },
	}, kit, device, genesis)
	require.NoError(t, err)
	require.Zero(t, genesisResult.ReadResult.PublicationCount)
	require.NoError(t, store.PutVaultSelection(ctx, state.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID, RecordedAt: clock.Unix()}))
	require.NoError(t, store.PutVaultCheckpoint(ctx, state.VaultCheckpoint{
		Vault: genesis.Vault, Anchor: genesis.Anchor, ControlCID: bytes.Clone(genesis.ControlCID), ControlBytes: bytes.Clone(genesis.Control),
		SnapshotCID: bytes.Clone(genesis.SnapshotCID), Epoch: 0, PolicyDigest: genesis.PolicyDigest, RecordedAt: clock.Unix(),
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(ctx, state.AuthenticatedPositionEvidence{
		Vault: genesis.Vault, Epoch: 0, PolicyDigest: genesis.PolicyDigest, Policy: bytes.Clone(genesis.Policy),
		Control: bytes.Clone(genesis.Control), Head: bytes.Clone(genesis.Head), Certificates: [][]byte{bytes.Clone(genesis.Certificate)},
		CheckpointPosition: bytes.Clone(genesis.Checkpoint),
	}))
	publicationIO := atproto.ATProtoPublicationIO{
		Reader: reader, Transport: transport, BlobUploadLimit: blobLimit, DID: did,
		TrustAnchor: genesis.Anchor, ObservationStore: store, Clock: func() time.Time { return clock },
	}
	fixture := &publicationFixture{
		t: t, paths: paths, store: store, keyring: keyring, settings: settings, pds: pds,
		repoKey: repoKey, did: did, blobLimit: blobLimit, transport: transport, reader: reader, root: device, genesis: genesis,
		selection: service.VaultSelection{Vault: genesis.Vault, DeviceID: device.DeviceID}, kit: kit,
		canaries: registry, filePath: filePath,
	}
	fixture.coordinator = fixture.newCoordinator(publicationIO, clock)
	genesisRead, err := fixture.coordinator.Pull(ctx, fixture.selection)
	require.NoError(t, err)
	require.Zero(t, genesisRead.Read.PublicationCount)
	local := readLocalPlaintextCanaries(t, fixture)
	require.True(t, bytes.Contains(local, fileCanary))
	require.True(t, bytes.Contains(local, []byte(settingCanary)))
	publishResult, err := fixture.coordinator.Publish(ctx, fixture.selection)
	require.NoError(t, err)
	require.Equal(t, service.StatusCommitted, publishResult.Status)
	require.Equal(t, uint64(1), publishResult.PublicationCount)
	pulled, err := fixture.coordinator.Pull(ctx, fixture.selection)
	require.NoError(t, err)
	require.Equal(t, uint64(1), pulled.Read.PublicationCount)
	fixture.publishedPlaintext = bytes.Clone(pulled.Read.Plaintext)
	return fixture
}

func (fixture *publicationFixture) newCoordinator(publicationIO atproto.ATProtoPublicationIO, clock time.Time) *service.Coordinator {
	fixture.t.Helper()
	remote := service.VaultReader{Reader: atproto.VaultReader{Transport: fixture.transport, ObservationStore: fixture.store, Clock: func() time.Time { return clock }}}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: fixture.paths}, State: fixture.store, DeviceKeys: fixture.keyring,
		Trust:   service.StateTrustSource{State: fixture.store, Keyring: fixture.keyring},
		Session: publicationReadSession{did: fixture.did, methods: fixture.reader.VerificationMethods}, Remote: remote,
		Publisher: publicationPublisher{io: publicationIO}, Settings: fixture.settings,
		Paths: fixture.paths, Clock: func() time.Time { return clock },
	})
	require.NoError(fixture.t, err)
	return coordinator
}

func publicationAuditReader(transport atproto.Transport, did string) atproto.RevisionReader {
	if pds, ok := transport.(*atprototest.MemoryPDS); ok {
		method := pds.VerificationMethod()
		return atproto.RevisionReader{Transport: transport, DIDDocumentID: did, VerificationMethods: []atproto.VerificationMethod{{
			ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
		}}}
	}
	return atproto.RevisionReader{Transport: transport, DIDDocumentID: did}
}

func publicationAuditTargets(t *testing.T, fileID, settingsID string) (config.Target, config.Target) {
	t.Helper()
	keys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	return config.Target{ID: fileID, Source: model.SourceFiles, Mode: config.Review,
			Root: &config.Root{Base: model.RootHome, Path: "dottie-private", Kind: model.SelectionDirectory}},
		config.Target{ID: settingsID, Source: model.SourceGNOME, Mode: config.Review,
			GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalApproved, Categories: []string{"appearance"}, MatrixVersion: matrix.Version, KeyDigest: fmt.Sprintf("%x", digest[:])}}
}

func publicationAuditGenesis(t *testing.T, kit []byte, root vault.DeviceMaterial) vault.Genesis {
	t.Helper()
	var contentKey [32]byte
	var wrapNonce [24]byte
	var publicationID [16]byte
	var nonce [24]byte
	_, err := rand.Read(contentKey[:])
	require.NoError(t, err)
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = rand.Read(wrapNonce[:])
	require.NoError(t, err)
	_, err = rand.Read(publicationID[:])
	require.NoError(t, err)
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "synthetic publication privacy fixture", RootDevice: root,
		ContentKey: contentKey[:], Wraps: []vault.RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: wrapNonce}},
		PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	return genesis
}

func readLocalPlaintextCanaries(t *testing.T, fixture *publicationFixture) []byte {
	t.Helper()
	configuration, err := os.ReadFile(filepath.Join(fixture.paths.AppConfigDir(), config.FileName))
	require.NoError(t, err)
	file, err := os.ReadFile(fixture.filePath)
	require.NoError(t, err)
	return bytes.Join([][]byte{configuration, file, []byte(fixture.settings.settingCanary), []byte(fixture.paths.Home), []byte(fixture.paths.ConfigHome)}, []byte("\n"))
}

type publicationAuditSurface struct {
	repoBytes   []byte
	blocks      map[string][]byte
	records     map[string][]byte
	recordPages map[string][][]byte
	listBlobs   []string
	blobs       map[string][]byte
	reachables  map[string]bool
	incomplete  []string
}

func collectPublicationAudit(ctx context.Context, publicTransport, authoredTransport atproto.Transport, did string, uploaded []string) publicationAuditSurface {
	surface := publicationAuditSurface{blocks: make(map[string][]byte), records: make(map[string][]byte), recordPages: make(map[string][][]byte), blobs: make(map[string][]byte), reachables: make(map[string]bool)}
	status, stream, err := publicTransport.OpenStream(ctx, "com.atproto.sync.getRepo", url.Values{"did": {did}})
	if err != nil || status != 200 || stream == nil {
		surface.incomplete = append(surface.incomplete, "getRepo")
	} else {
		data, readErr := io.ReadAll(io.LimitReader(stream, (8<<20)+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || len(data) > 8<<20 {
			surface.incomplete = append(surface.incomplete, "getRepo bounded read")
		} else {
			surface.repoBytes = data
			reader, carErr := car.NewCarReader(bytes.NewReader(data))
			if carErr != nil {
				surface.incomplete = append(surface.incomplete, "getRepo CAR parse")
			} else {
				for {
					block, nextErr := reader.Next()
					if errors.Is(nextErr, io.EOF) {
						break
					}
					if nextErr != nil {
						surface.incomplete = append(surface.incomplete, "getRepo CAR block iteration")
						break
					}
					surface.blocks[block.Cid().String()] = bytes.Clone(block.RawData())
				}
			}
		}
	}
	for _, collection := range publicationAuditCollections {
		cursor := ""
		seenCursors := make(map[string]bool)
		for page := 0; page < 1000; page++ {
			query := url.Values{"repo": {did}, "collection": {collection}, "limit": {"100"}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			status, body, err := publicTransport.Do(ctx, "GET", "com.atproto.repo.listRecords", query, nil, "")
			if err != nil || status != 200 {
				surface.incomplete = append(surface.incomplete, fmt.Sprintf("listRecords %s status=%d error=%v", collection, status, err))
				break
			}
			var listing struct {
				Records json.RawMessage `json:"records"`
				Cursor  *string         `json:"cursor"`
			}
			var records []json.RawMessage
			if json.Unmarshal(body, &listing) != nil || len(listing.Records) == 0 || json.Unmarshal(listing.Records, &records) != nil {
				surface.incomplete = append(surface.incomplete, "listRecords JSON "+collection)
				break
			}
			surface.recordPages[collection] = append(surface.recordPages[collection], bytes.Clone(body))
			if listing.Cursor == nil || *listing.Cursor == "" {
				break
			}
			if seenCursors[*listing.Cursor] || page == 999 {
				surface.incomplete = append(surface.incomplete, "listRecords cursor bound "+collection)
				break
			}
			seenCursors[*listing.Cursor] = true
			cursor = *listing.Cursor
		}
		if pages := surface.recordPages[collection]; len(pages) != 0 {
			surface.records[collection] = bytes.Join(pages, []byte("\n"))
		}
	}
	cursor := ""
	seenCursors := make(map[string]bool)
	listed := make(map[string]bool)
	for page := 0; page < 1000; page++ {
		query := url.Values{"did": {did}, "limit": {"100"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		status, body, err := authoredTransport.Do(ctx, "GET", "com.atproto.sync.listBlobs", query, nil, "")
		if err != nil || status != 200 {
			surface.incomplete = append(surface.incomplete, fmt.Sprintf("listBlobs status=%d error=%v", status, err))
			break
		}
		var listing struct {
			CIDs   []string `json:"cids"`
			Cursor *string  `json:"cursor"`
		}
		if json.Unmarshal(body, &listing) != nil {
			surface.incomplete = append(surface.incomplete, "listBlobs JSON")
			break
		}
		for _, blobCID := range listing.CIDs {
			listed[blobCID] = true
		}
		if listing.Cursor == nil || *listing.Cursor == "" {
			break
		}
		if seenCursors[*listing.Cursor] || page == 999 {
			surface.incomplete = append(surface.incomplete, "listBlobs cursor bound")
			break
		}
		seenCursors[*listing.Cursor] = true
		cursor = *listing.Cursor
	}
	for blobCID := range listed {
		surface.listBlobs = append(surface.listBlobs, blobCID)
	}
	sort.Strings(surface.listBlobs)
	toFetch := make(map[string]bool)
	for _, blobCID := range surface.listBlobs {
		toFetch[blobCID] = true
	}
	for _, pages := range surface.recordPages {
		for _, body := range pages {
			for _, blobCID := range jsonBlobCIDs(body) {
				toFetch[blobCID] = true
			}
		}
	}
	for _, blobCID := range uploaded {
		toFetch[blobCID] = true
		surface.reachables[blobCID] = false
	}
	for blobCID := range toFetch {
		surface.reachables[blobCID] = false
		status, stream, err := publicTransport.OpenStream(ctx, "com.atproto.sync.getBlob", url.Values{"did": {did}, "cid": {blobCID}})
		if err != nil || stream == nil {
			surface.incomplete = append(surface.incomplete, "getBlob "+blobCID)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, (16<<20)+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || len(data) > 16<<20 {
			surface.incomplete = append(surface.incomplete, "getBlob bounded read "+blobCID)
			continue
		}
		if status >= 200 && status < 300 {
			surface.blobs[blobCID] = data
			surface.reachables[blobCID] = true
		} else if status != 404 {
			surface.incomplete = append(surface.incomplete, "getBlob status "+blobCID)
		}
	}
	return surface
}

func jsonBlobCIDs(data []byte) []string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return nil
	}
	found := make(map[string]bool)
	var walk func(any)
	walk = func(current any) {
		switch item := current.(type) {
		case map[string]any:
			if ref, ok := item["ref"].(map[string]any); ok {
				if value, ok := ref["$link"].(string); ok && value != "" {
					found[value] = true
				}
			}
			for _, nested := range item {
				walk(nested)
			}
		case []any:
			for _, nested := range item {
				walk(nested)
			}
		}
	}
	walk(value)
	result := make([]string, 0, len(found))
	for blobCID := range found {
		result = append(result, blobCID)
	}
	sort.Strings(result)
	return result
}

func scanPublicationCanaries(data []byte, registry publicationCanaries, classes ...publicationAuditClass) []string {
	allowed := make(map[publicationAuditClass]bool)
	for _, class := range classes {
		allowed[class] = true
	}
	findings := make([]string, 0)
	for _, item := range registry.items {
		if !allowed[item.class] {
			continue
		}
		for _, form := range item.forms {
			if len(form) != 0 && bytes.Contains(data, form) {
				findings = append(findings, item.name)
				break
			}
		}
	}
	sort.Strings(findings)
	return findings
}

func assertPublicationCanariesAbsent(t *testing.T, surfaceName string, data []byte, registry publicationCanaries, classes ...publicationAuditClass) {
	t.Helper()
	assert.Empty(t, scanPublicationCanaries(data, registry, classes...), "%s contains a forbidden canary", surfaceName)
}

func assertPublicationCanaryPresent(t *testing.T, surfaceName string, data []byte, registry publicationCanaries, name string) {
	t.Helper()
	for _, item := range registry.items {
		if item.name != name {
			continue
		}
		for _, form := range item.forms {
			if len(form) != 0 && bytes.Contains(data, form) {
				return
			}
		}
		assert.Fail(t, "expected canary was absent", "canary=%s surface=%s", name, surfaceName)
		return
	}
	require.FailNow(t, "canary is not registered: "+name)
}

func scanCompressedPublicationCanaries(data []byte, registry publicationCanaries) []string {
	findings := scanPublicationCanaries(data, registry, publicationConfidential, publicationCredential)
	if reader, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		decoded, readErr := io.ReadAll(io.LimitReader(reader, 1<<20+1))
		if readErr == nil && len(decoded) <= 1<<20 {
			findings = append(findings, scanPublicationCanaries(decoded, registry, publicationConfidential, publicationCredential)...)
		}
		_ = reader.Close()
	}
	if reader, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		decoded, readErr := io.ReadAll(io.LimitReader(reader, 1<<20+1))
		if readErr == nil && len(decoded) <= 1<<20 {
			findings = append(findings, scanPublicationCanaries(decoded, registry, publicationConfidential, publicationCredential)...)
		}
		_ = reader.Close()
	}
	sort.Strings(findings)
	return findings
}

func publicationAuditFindings(surface publicationAuditSurface, registry publicationCanaries) []string {
	findings := append([]string(nil), surface.incomplete...)
	findings = append(findings, scanPublicationCanaries(surface.repoBytes, registry, publicationConfidential, publicationCredential)...)
	for cidText, block := range surface.blocks {
		for _, match := range scanPublicationCanaries(block, registry, publicationConfidential, publicationCredential) {
			findings = append(findings, "CAR block "+cidText+" "+match)
		}
	}
	for collection, body := range surface.records {
		for _, match := range scanPublicationCanaries(body, registry, publicationConfidential, publicationCredential) {
			findings = append(findings, "listRecords "+collection+" "+match)
		}
	}
	for blobCID, body := range surface.blobs {
		for _, match := range scanCompressedPublicationCanaries(body, registry) {
			findings = append(findings, "getBlob "+blobCID+" "+match)
		}
	}
	sort.Strings(findings)
	return findings
}

func auditBlobReferences(surface publicationAuditSurface, referenceIntegrityCIDs []string, public func(string) bool) (referenced, live, retrievable map[string]bool, findings []string) {
	referenced = make(map[string]bool)
	live = make(map[string]bool)
	retrievable = make(map[string]bool)
	for _, blobCID := range surface.listBlobs {
		live[blobCID] = true
	}
	for _, pages := range surface.recordPages {
		for _, body := range pages {
			for _, blobCID := range jsonBlobCIDs(body) {
				referenced[blobCID] = true
			}
		}
	}
	for blobCID, reachable := range surface.reachables {
		if reachable {
			retrievable[blobCID] = true
		}
	}
	for _, blobCID := range referenceIntegrityCIDs {
		if !referenced[blobCID] {
			findings = append(findings, "retained orphan "+blobCID)
		}
		if public != nil && public(blobCID) && !referenced[blobCID] {
			findings = append(findings, "publicly exposed orphan "+blobCID)
		}
	}
	for blobCID := range retrievable {
		if !referenced[blobCID] {
			findings = append(findings, "retrievable orphan "+blobCID)
		}
	}
	sort.Strings(findings)
	return referenced, live, retrievable, findings
}

var publicationRecordKeyAllowlist = map[string][]string{
	atproto.VaultSnapshotNSID:    {"$.$type", "$.schemaVersion", "$.vault", "$.publicationId", "$.epochSeq", "$.policyDigest", "$.parent", "$.blob", "$.signerDeviceId", "$.signerKeyId", "$.envelopeSignatureDigest", "$.signature", "$.blob.$type", "$.blob.ref", "$.blob.mimeType", "$.blob.size", "$.blob.ref.$link"},
	atproto.VaultHeadNSID:        {"$.$type", "$.schemaVersion", "$.vault", "$.epochSeq", "$.policyDigest", "$.snapshotCid", "$.blobCid", "$.publicationCount", "$.prevHeadCid", "$.signerDeviceId", "$.signerKeyId", "$.signature"},
	atproto.VaultControlNSID:     {"$.$type", "$.schemaVersion", "$.vault", "$.epochSeq", "$.policyDigest", "$.headSnapshotCid", "$.revoked", "$.prevControlCid", "$.signerDeviceId", "$.signerKeyId", "$.signature", "$.revoked[].deviceId", "$.revoked[].certEpoch"},
	atproto.VaultPolicyNSID:      {"$.$type", "$.schemaVersion", "$.vault", "$.epochSeq", "$.roles", "$.recipients", "$.policyRetentionFloor", "$.retainedRecoveryPoints", "$.maxPublications", "$.maxEpochAge", "$.recoveryAnchor", "$.prevPolicyDigest", "$.signerDeviceId", "$.signerKeyId", "$.signature", "$.roles[].deviceId", "$.roles[].role", "$.recipients[].deviceId", "$.recipients[].keyId", "$.recipients[].publicKey"},
	atproto.VaultCertificateNSID: {"$.$type", "$.schemaVersion", "$.vault", "$.deviceId", "$.keyId", "$.signingPublicKey", "$.encryptionPublicKey", "$.role", "$.certEpoch", "$.issuer", "$.revocationRef", "$.signerDeviceId", "$.signerKeyId", "$.signature"},
	atproto.VaultCheckpointNSID:  {"$.$type", "$.schemaVersion", "$.vault", "$.snapshotCid", "$.epochSeq", "$.policyDigest", "$.anchor", "$.controlCid", "$.signerDeviceId", "$.signerKeyId", "$.signature"},
	atproto.VaultAttestationNSID: {"$.$type", "$.schemaVersion", "$.vault", "$.deviceId", "$.policyDigest", "$.retentionFloor", "$.retainedRecoveryPoints", "$.recoveryPoints", "$.controlCid", "$.signerDeviceId", "$.signerKeyId", "$.signature", "$.recoveryPoints[].epoch", "$.recoveryPoints[].snapshotCid"},
}

func recordKeyInventory(record map[string]any) ([]string, error) {
	typeID, ok := record["$type"].(string)
	if !ok {
		return nil, errors.New("record has no type")
	}
	allowed, ok := publicationRecordKeyAllowlist[typeID]
	if !ok {
		return nil, fmt.Errorf("record type is not inventoried: %s", typeID)
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, path := range allowed {
		allowedSet[path] = true
	}
	found := make(map[string]bool)
	var walk func(any, string) error
	walk = func(current any, path string) error {
		switch item := current.(type) {
		case atdata.Blob:
			blob := map[string]any{
				"$type": "blob", "ref": map[string]any{"$link": item.Ref.String()},
				"mimeType": item.MimeType, "size": item.Size,
			}
			return walk(blob, path)
		case map[string]any:
			for key, nested := range item {
				child := path + "." + key
				found[child] = true
				if !allowedSet[child] {
					return fmt.Errorf("unexpected record key %s: %s", child, typeID)
				}
				if err := walk(nested, child); err != nil {
					return err
				}
			}
		case []any:
			for _, nested := range item {
				if err := walk(nested, path+"[]"); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(record, "$"); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func auditRecordKeyInventory(surface publicationAuditSurface) error {
	seen := 0
	for _, block := range surface.blocks {
		object, err := atdata.UnmarshalCBOR(block)
		if err != nil || object["$type"] == nil {
			continue
		}
		typeID, _ := object["$type"].(string)
		if _, dottie := publicationRecordKeyAllowlist[typeID]; !dottie {
			continue
		}
		if _, err := recordKeyInventory(object); err != nil {
			return err
		}
		seen++
	}
	if seen == 0 {
		return errors.New("no Dottie records were inventoried")
	}
	return nil
}

type publicationStateDigest struct {
	ConfigBytes    string
	Targets        any
	Bases          any
	Journal        any
	Checkpoint     any
	Position       any
	History        any
	Retention      any
	KeyringDigest  string
	SettingsDigest string
}

func (fixture *publicationFixture) logicalStateDigest() string {
	fixture.t.Helper()
	ctx := context.Background()
	configBytes, err := os.ReadFile(filepath.Join(fixture.paths.AppConfigDir(), config.FileName))
	require.NoError(fixture.t, err)
	bases := make(map[string]any)
	for _, targetID := range []string{publicationAuditFileTargetID, publicationAuditSettingsTargetID} {
		entries, baseErr := fixture.store.AppliedBase(ctx, targetID)
		require.NoError(fixture.t, baseErr)
		bases[targetID] = entries
	}
	journal, err := fixture.store.JournalEntriesAll(ctx)
	require.NoError(fixture.t, err)
	checkpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(fixture.t, err)
	position, err := fixture.store.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, 0, fixture.genesis.PolicyDigest)
	require.NoError(fixture.t, err)
	history, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(fixture.t, err)
	retention, err := fixture.store.RetentionInventory(ctx, fixture.genesis.Vault, fixture.root.DeviceID)
	require.NoError(fixture.t, err)
	targets, err := fixture.store.LocalHistorySummaries(ctx, 32)
	require.NoError(fixture.t, err)
	configuration, err := config.Load(fixture.paths)
	require.NoError(fixture.t, err)
	targetInventory := map[string]any{"configuration": configuration.Targets, "state": targets}
	settingsDigest := sha256.Sum256([]byte(fixture.settings.settingCanary))
	value := publicationStateDigest{
		ConfigBytes: hex.EncodeToString(configBytes), Targets: targetInventory, Bases: bases, Journal: journal,
		Checkpoint: checkpoint, Position: position, History: history, Retention: retention,
		KeyringDigest: fixture.keyringDigest(), SettingsDigest: hex.EncodeToString(settingsDigest[:]),
	}
	encoded, err := json.Marshal(value)
	require.NoError(fixture.t, err)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (fixture *publicationFixture) keyringDigest() string {
	fixture.t.Helper()
	devices := make([]string, 0, len(fixture.keyring.devices))
	for deviceID := range fixture.keyring.devices {
		devices = append(devices, deviceID)
	}
	sort.Strings(devices)
	h := sha256.New()
	for _, deviceID := range devices {
		device := fixture.keyring.devices[deviceID]
		h.Write([]byte(deviceID))
		h.Write(device.KeyID)
		h.Write(device.Signing)
		if device.Recipient != nil {
			h.Write(device.Recipient.Bytes())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (fixture *publicationFixture) applicationStateDigest() string {
	fixture.t.Helper()
	ctx := context.Background()
	configBytes, err := os.ReadFile(filepath.Join(fixture.paths.AppConfigDir(), config.FileName))
	require.NoError(fixture.t, err)
	bases := make(map[string]any)
	for _, targetID := range []string{publicationAuditFileTargetID, publicationAuditSettingsTargetID} {
		entries, baseErr := fixture.store.AppliedBase(ctx, targetID)
		require.NoError(fixture.t, baseErr)
		bases[targetID] = entries
	}
	journal, err := fixture.store.JournalEntriesAll(ctx)
	require.NoError(fixture.t, err)
	checkpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(fixture.t, err)
	targets, err := fixture.store.LocalHistorySummaries(ctx, 32)
	require.NoError(fixture.t, err)
	configuration, err := config.Load(fixture.paths)
	require.NoError(fixture.t, err)
	settingsDigest := sha256.Sum256([]byte(fixture.settings.settingCanary))
	value := struct {
		ConfigBytes    string
		Targets        any
		Bases          any
		Journal        any
		Checkpoint     any
		SettingsDigest string
		KeyringDigest  string
	}{hex.EncodeToString(configBytes), map[string]any{"configuration": configuration.Targets, "state": targets}, bases, journal, checkpoint, hex.EncodeToString(settingsDigest[:]), fixture.keyringDigest()}
	encoded, err := json.Marshal(value)
	require.NoError(fixture.t, err)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (fixture *publicationFixture) homeTreeDigest() string {
	fixture.t.Helper()
	h := sha256.New()
	for _, root := range []string{fixture.paths.Home, fixture.paths.ConfigHome, fixture.paths.CacheHome, fixture.paths.DataHome} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s\x00%s\x00%o\x00", root, relative, info.Mode())
			if info.Mode().IsRegular() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				h.Write(data)
			} else if info.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(path)
				if err != nil {
					return err
				}
				h.Write([]byte(link))
			}
			return nil
		})
		require.NoError(fixture.t, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (fixture *publicationFixture) runOfflineCLI(args ...string) (int, string, string) {
	fixture.t.Helper()
	require.NoError(fixture.t, fixture.store.Close())
	oldHome, hadHome := os.LookupEnv("HOME")
	oldConfig, hadConfig := os.LookupEnv("XDG_CONFIG_HOME")
	oldState, hadState := os.LookupEnv("XDG_STATE_HOME")
	oldCache, hadCache := os.LookupEnv("XDG_CACHE_HOME")
	oldData, hadData := os.LookupEnv("XDG_DATA_HOME")
	require.NoError(fixture.t, os.Setenv("HOME", fixture.paths.Home))
	require.NoError(fixture.t, os.Setenv("XDG_CONFIG_HOME", fixture.paths.ConfigHome))
	require.NoError(fixture.t, os.Setenv("XDG_STATE_HOME", fixture.paths.StateHome))
	require.NoError(fixture.t, os.Setenv("XDG_CACHE_HOME", fixture.paths.CacheHome))
	require.NoError(fixture.t, os.Setenv("XDG_DATA_HOME", fixture.paths.DataHome))
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, &stdout, &stderr)
	for _, item := range []struct {
		key string
		val string
		had bool
	}{{"HOME", oldHome, hadHome}, {"XDG_CONFIG_HOME", oldConfig, hadConfig}, {"XDG_STATE_HOME", oldState, hadState}, {"XDG_CACHE_HOME", oldCache, hadCache}, {"XDG_DATA_HOME", oldData, hadData}} {
		if item.had {
			require.NoError(fixture.t, os.Setenv(item.key, item.val))
		} else {
			require.NoError(fixture.t, os.Unsetenv(item.key))
		}
	}
	reopened, err := state.Open(fixture.paths)
	require.NoError(fixture.t, err)
	fixture.t.Cleanup(func() { assert.NoError(fixture.t, reopened.Close()) })
	fixture.store = reopened
	fixture.coordinator = fixture.newCoordinator(atproto.ATProtoPublicationIO{
		Reader: fixture.reader, Transport: fixture.transport, BlobUploadLimit: 1 << 20, DID: publicationAuditDID,
		TrustAnchor: fixture.genesis.Anchor, ObservationStore: reopened,
	}, time.Unix(1_800_000_000, 0))
	return code, stdout.String(), stderr.String()
}

func seedPlaintextRecord(t *testing.T, pds *atprototest.MemoryPDS, collection, rkey, canary string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"$type": collection, "value": canary})
	require.NoError(t, err)
	_, _, err = publicationAuditApplyRecord(context.Background(), pds, pds.CurrentRevision().CommitCID.String(), "create", collection, rkey, body)
	require.NoError(t, err)
}

func seedBlobReferenceRecord(t *testing.T, pds *atprototest.MemoryPDS, rkey string, data []byte) string {
	t.Helper()
	blob := publicationAuditUploadBlob(t, pds, data)
	body, err := json.Marshal(map[string]any{"$type": publicationAuditCollection, "blob": blob})
	require.NoError(t, err)
	_, _, err = publicationAuditApplyRecord(context.Background(), pds, pds.CurrentRevision().CommitCID.String(), "create", publicationAuditCollection, rkey, body)
	require.NoError(t, err)
	return blob.Ref.CID().String()
}

func publicationAuditUploadBlob(t *testing.T, pds *atprototest.MemoryPDS, data []byte) atdata.Blob {
	t.Helper()
	status, body, err := pds.Do(context.Background(), "POST", "com.atproto.repo.uploadBlob", nil, data, "application/octet-stream")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	var result struct {
		Blob atdata.Blob `json:"blob"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	return result.Blob
}

func publicationAuditApplyRecord(ctx context.Context, pds *atprototest.MemoryPDS, swapCommit, action, collection, rkey string, value []byte) (int, []byte, error) {
	var raw json.RawMessage = value
	if action == "delete" {
		raw = nil
	}
	body, err := json.Marshal(map[string]any{
		"repo": publicationAuditDID, "swapCommit": swapCommit,
		"writes": []any{map[string]any{"$type": "com.atproto.repo.applyWrites#" + action, "collection": collection, "rkey": rkey, "value": raw}},
	})
	if err != nil {
		return 0, nil, err
	}
	return pds.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, body, "application/json")
}

func compressedPublicationCanary(t *testing.T, value string, useGzip bool) []byte {
	t.Helper()
	payload := []byte(strings.Repeat(value+"|", 64))
	var output bytes.Buffer
	if useGzip {
		writer, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
		require.NoError(t, err)
		_, err = writer.Write(payload)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
	} else {
		writer, err := zlib.NewWriterLevel(&output, zlib.BestCompression)
		require.NoError(t, err)
		_, err = writer.Write(payload)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
	}
	return output.Bytes()
}
