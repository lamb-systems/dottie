package integration

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	spacesCapacitySTARResponseBytes          = 16 * 1024 * 1024
	spacesCapacityApplicationBytes           = 8 * 1024 * 1024
	spacesCapacityProtocolReserveBytes       = spacesCapacitySTARResponseBytes - spacesCapacityApplicationBytes
	spacesCapacityPolicyResponseBytes        = 64 * 1024
	spacesCapacityRecordBytes                = 2 * 1024
	spacesCapacityApplicationRecordCount     = 4096
	spacesCapacityCorrectiveReserve          = 16
	spacesCapacityReadAttempts               = 3
	spacesCapacityReadOperations             = 6
	spacesCapacityLineageLinks               = 4094
	spacesCapacityBlobBytes                  = 384 * 1024 * 1024
	spacesCapacityAssumedRecordOverheadBytes = 512
	spacesCapacityAssumedFixedCommitMACBytes = 64 * 1024
	spacesCapacitySlowPublicationsPerDay     = 1
	spacesCapacityFastPublicationsPerDay     = 24
	spacesCapacitySHA256Passes               = 4
)

type spacesCapacityPoint struct {
	publications int
	records      int
	appBytes     int
	protoBytes   int
	response     int
}

func spacesCapacityReadPoint(publications int) spacesCapacityPoint {
	records := publications + 1
	appBytes := records * spacesCapacityRecordBytes
	protoBytes := records*spacesCapacityAssumedRecordOverheadBytes + spacesCapacityAssumedFixedCommitMACBytes
	return spacesCapacityPoint{
		publications: publications,
		records:      records,
		appBytes:     appBytes,
		protoBytes:   protoBytes,
		response:     appBytes + protoBytes,
	}
}

func TestSpacesCapacityModelledReadCostCurve(t *testing.T) {
	snapshotCapByRecordCount := spacesCapacityApplicationRecordCount - 1
	snapshotCapByApplicationBytes := spacesCapacityApplicationBytes/spacesCapacityRecordBytes - 1
	publicationCap := snapshotCapByRecordCount
	if snapshotCapByApplicationBytes < publicationCap {
		publicationCap = snapshotCapByApplicationBytes
	}
	ordinaryCap := publicationCap - spacesCapacityCorrectiveReserve
	require.Equal(t, 4095, publicationCap)
	require.Equal(t, 4079, ordinaryCap)
	require.Equal(t, 4094, publicationCap-1)
	require.LessOrEqual(t, spacesCapacityLineageLinks, publicationCap-1)

	t.Logf("modelled inputs: STAR response=%d bytes (P10 §8.1 proposed profile); application records=%d bytes (P10 §8.1 proposed profile); protocol reserve=%d bytes (P10 §8.1 proposed profile); policy=%d bytes (P10 §8.1 proposed profile); record=%d bytes (P10 §8.1 proposed profile); record count=%d including one head (P10 §8.1 proposed profile); corrective reserve=%d publications (P10 §8.1 proposed profile); attempts/read=%d (P10 §8.1 proposed profile); read operations/workflow=%d (P10 §8.1 proposed profile); lineage links=%d (P10 §8.1 proposed profile); blob=%d bytes (P10 §8.1 proposed profile); assumed record overhead=%d bytes/record (model assumption); assumed fixed commit/MAC overhead=%d bytes (model assumption); rates=%d and %d publications/day (P10 §8.1 examples)", spacesCapacitySTARResponseBytes, spacesCapacityApplicationBytes, spacesCapacityProtocolReserveBytes, spacesCapacityPolicyResponseBytes, spacesCapacityRecordBytes, spacesCapacityApplicationRecordCount, spacesCapacityCorrectiveReserve, spacesCapacityReadAttempts, spacesCapacityReadOperations, spacesCapacityLineageLinks, spacesCapacityBlobBytes, spacesCapacityAssumedRecordOverheadBytes, spacesCapacityAssumedFixedCommitMACBytes, spacesCapacitySlowPublicationsPerDay, spacesCapacityFastPublicationsPerDay)
	t.Logf("modelled cap formula: min(%d-1, floor((%d-%d)/%d)-1) = min(%d,%d) = %d snapshots; ordinary cap=%d; sequences=0..%d", spacesCapacityApplicationRecordCount, spacesCapacitySTARResponseBytes, spacesCapacityApplicationBytes, spacesCapacityRecordBytes, snapshotCapByRecordCount, snapshotCapByApplicationBytes, publicationCap, ordinaryCap, publicationCap-1)

	points := []int{0, 1, 100, ordinaryCap, publicationCap}
	for _, publications := range points {
		point := spacesCapacityReadPoint(publications)
		assert.LessOrEqual(t, point.appBytes, spacesCapacityApplicationBytes)
		assert.LessOrEqual(t, point.response, spacesCapacitySTARResponseBytes)
		t.Logf("modelled read-cost curve: snapshots=%d records=%d application=%d bytes assumed-protocol-overhead=%d bytes total=%d bytes", point.publications, point.records, point.appBytes, point.protoBytes, point.response)
	}
	maxPoint := spacesCapacityReadPoint(publicationCap)
	maxRecordOverhead := (spacesCapacityProtocolReserveBytes - spacesCapacityAssumedFixedCommitMACBytes) / spacesCapacityApplicationRecordCount
	require.Equal(t, 2032, maxRecordOverhead)
	require.LessOrEqual(t, spacesCapacityAssumedRecordOverheadBytes, maxRecordOverhead)
	t.Logf("modelled overhead pass condition: per-record overhead <= (%d - %d)/%d = %d bytes (%.3f KiB); assumed overhead=%d bytes; maximum application records=%d; total modelled read=%s", spacesCapacityProtocolReserveBytes, spacesCapacityAssumedFixedCommitMACBytes, spacesCapacityApplicationRecordCount, maxRecordOverhead, float64(maxRecordOverhead)/1024, spacesCapacityAssumedRecordOverheadBytes, spacesCapacityApplicationRecordCount, formatSpacesCapacityBytes(maxPoint.response))

	ordinaryDaysAtSlowRate := float64(ordinaryCap) / spacesCapacitySlowPublicationsPerDay
	ordinaryDaysAtFastRate := float64(ordinaryCap) / spacesCapacityFastPublicationsPerDay
	t.Logf("modelled ordinary-cap horizon: %d / %d publications/day = %.2f days = %.2f years; %d / %d publications/day = %.2f days", ordinaryCap, spacesCapacitySlowPublicationsPerDay, ordinaryDaysAtSlowRate, ordinaryDaysAtSlowRate/365.25, ordinaryCap, spacesCapacityFastPublicationsPerDay, ordinaryDaysAtFastRate)
	assert.InDelta(t, 11.17, ordinaryDaysAtSlowRate/365.25, 0.02)
	assert.InDelta(t, 170.0, ordinaryDaysAtFastRate, 1.0)

	starBytesPerReadOperation := spacesCapacityReadAttempts * spacesCapacitySTARResponseBytes
	policyBytesPerReadOperation := spacesCapacityReadAttempts * spacesCapacityPolicyResponseBytes
	workflowSTARBytes := spacesCapacityReadOperations * starBytesPerReadOperation
	workflowPolicyBytes := spacesCapacityReadOperations * policyBytesPerReadOperation
	workflowBlobBytes := spacesCapacityReadOperations * spacesCapacityBlobBytes
	require.Equal(t, 48*1024*1024, starBytesPerReadOperation)
	require.Equal(t, 288*1024*1024, workflowSTARBytes)
	require.Equal(t, 18*spacesCapacityPolicyResponseBytes, workflowPolicyBytes)
	t.Logf("modelled read-attempt bound: per current-read operation STAR=%s and policy=%s; six-operation workflow STAR=%s and policy=%s; conservative six-selected-blob bound=%s; blob cap is per operation and actual workflow selection count is path-dependent", formatSpacesCapacityBytes(starBytesPerReadOperation), formatSpacesCapacityBytes(policyBytesPerReadOperation), formatSpacesCapacityBytes(workflowSTARBytes), formatSpacesCapacityBytes(workflowPolicyBytes), formatSpacesCapacityBytes(workflowBlobBytes))
}

func TestSpacesCapacityLocalSHA256Measurement(t *testing.T) {
	buffer := make([]byte, spacesCapacitySTARResponseBytes)
	for index := range buffer {
		buffer[index] = byte(index * 31)
	}
	var digest byte
	start := time.Now()
	for pass := 0; pass < spacesCapacitySHA256Passes; pass++ {
		sum := sha256.Sum256(buffer)
		digest ^= sum[pass]
	}
	elapsed := time.Since(start)
	require.True(t, elapsed > 0)
	measuredBytes := spacesCapacitySTARResponseBytes * spacesCapacitySHA256Passes
	measuredBytesPerSecond := float64(measuredBytes) / elapsed.Seconds()
	require.True(t, measuredBytesPerSecond > 0)
	modelledMaximumReadHashSeconds := float64(spacesCapacitySTARResponseBytes) / measuredBytesPerSecond
	t.Logf("MEASURED local SHA-256 throughput: %.2f MiB/s over %s input bytes in %s; equivalent full 16 MiB buffer extrapolation=%.4f s; measured locally in Go test, not STAR/LtHash, not a provider measurement, not an end-to-end read time; digest guard=%d", measuredBytesPerSecond/(1024*1024), formatSpacesCapacityBytes(measuredBytes), elapsed, modelledMaximumReadHashSeconds, digest)
}

func formatSpacesCapacityBytes(value int) string {
	return fmt.Sprintf("%.3f MiB (%d bytes)", float64(value)/(1024*1024), value)
}
