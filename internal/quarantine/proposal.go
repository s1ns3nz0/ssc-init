package quarantine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const ProposalSchemaV1 = "ssc-init.quarantine-proposal.v1"

type Selection struct {
	AssetID       string `json:"assetId"`
	ObservationID string `json:"observationId"`
	EvidenceID    string `json:"evidenceId"`
}

func EligibleSelections(inventory model.Inventory, assetID string) []Selection {
	selections := []Selection{}
	for _, evidence := range inventory.Evidence {
		selection := Selection{AssetID: assetID, ObservationID: evidence.ObservationID, EvidenceID: evidence.ID}
		if evidence.AssetID != assetID {
			continue
		}
		if _, _, ok := eligibleSelection(inventory, selection); ok {
			selections = append(selections, selection)
		}
	}
	sort.Slice(selections, func(i, j int) bool {
		if selections[i].ObservationID != selections[j].ObservationID {
			return selections[i].ObservationID < selections[j].ObservationID
		}
		return selections[i].EvidenceID < selections[j].EvidenceID
	})
	if len(selections) > 64 {
		selections = selections[:64]
	}
	return selections
}

type Proposal struct {
	SchemaVersion string `json:"schemaVersion"`
	ApprovalID    string `json:"approvalId"`
	RecordID      string `json:"recordId"`
	AssetID       string `json:"assetId"`
	ObservationID string `json:"observationId"`
	EvidenceID    string `json:"evidenceId"`
	OriginalRef   string `json:"originalRef"`
	SHA256        string `json:"sha256"`
	OriginalMode  uint32 `json:"originalMode"`
	Action        string `json:"action"`
}

func (p Proposal) Valid() bool {
	if p.SchemaVersion != ProposalSchemaV1 || p.Action != "quarantine" && p.Action != "restore" || !safeID(p.ApprovalID) {
		return false
	}
	record := p.record()
	record.State = StateRequested
	record.RequestedAt = proposalEpoch
	return record.Valid() && p.ApprovalID == proposalApproval(p)
}

func (p Proposal) record() Record {
	return Record{ID: p.RecordID, AssetID: p.AssetID, ObservationID: p.ObservationID, EvidenceID: p.EvidenceID, OriginalRef: p.OriginalRef, SHA256: p.SHA256, OriginalMode: p.OriginalMode}
}

var proposalEpoch = time.Unix(1, 0).UTC()

func (m Manager) Preview(ctx context.Context, inventory model.Inventory, selection Selection) (Proposal, error) {
	observation, evidence, ok := eligibleSelection(inventory, selection)
	if !ok {
		return Proposal{}, ErrUnsafeSource
	}
	mode, err := m.verifyPreviewSource(ctx, observation.LocationRef, evidence.Digest)
	if err != nil {
		return Proposal{}, err
	}
	identity := sha256.Sum256([]byte("ssc-init.quarantine.record.v1\x00" + selection.AssetID + "\x00" + selection.ObservationID + "\x00" + selection.EvidenceID + "\x00" + evidence.Digest))
	proposal := Proposal{SchemaVersion: ProposalSchemaV1, RecordID: fmt.Sprintf("quarantine:sha256:%x", identity), AssetID: selection.AssetID, ObservationID: selection.ObservationID, EvidenceID: selection.EvidenceID, OriginalRef: observation.LocationRef, SHA256: evidence.Digest, OriginalMode: mode, Action: "quarantine"}
	proposal.ApprovalID = proposalApproval(proposal)
	if !proposal.Valid() {
		return Proposal{}, ErrUnsafeSource
	}
	return proposal, nil
}

func (m Manager) Apply(ctx context.Context, inventory model.Inventory, selection Selection, approvalID string) (Record, error) {
	proposal, err := m.Preview(ctx, inventory, selection)
	if err != nil || subtle.ConstantTimeCompare([]byte(proposal.ApprovalID), []byte(approvalID)) != 1 {
		return Record{}, ErrQuarantineState
	}
	return m.Quarantine(ctx, proposal.record())
}

func (m Manager) PreviewRestore(record Record) (Proposal, error) {
	if !record.Valid() || record.State != StateQuarantined {
		return Proposal{}, ErrQuarantineState
	}
	proposal := Proposal{SchemaVersion: ProposalSchemaV1, RecordID: record.ID, AssetID: record.AssetID, ObservationID: record.ObservationID, EvidenceID: record.EvidenceID, OriginalRef: record.OriginalRef, SHA256: record.SHA256, OriginalMode: record.OriginalMode, Action: "restore"}
	proposal.ApprovalID = proposalApproval(proposal)
	if !proposal.Valid() {
		return Proposal{}, ErrQuarantineState
	}
	return proposal, nil
}

func (m Manager) ApplyRestore(ctx context.Context, record Record, approvalID string) (Record, error) {
	proposal, err := m.PreviewRestore(record)
	if err != nil || subtle.ConstantTimeCompare([]byte(proposal.ApprovalID), []byte(approvalID)) != 1 {
		return Record{}, ErrQuarantineState
	}
	return m.Restore(ctx, record)
}

func eligibleSelection(inventory model.Inventory, selection Selection) (model.Observation, model.ContentEvidence, bool) {
	var observation model.Observation
	for _, candidate := range inventory.Observations {
		if candidate.ID == selection.ObservationID && candidate.AssetID == selection.AssetID {
			observation = candidate
			break
		}
	}
	if observation.ID == "" || !strings.HasPrefix(observation.LocationRef, "$HOME/") {
		return model.Observation{}, model.ContentEvidence{}, false
	}
	for _, evidence := range inventory.Evidence {
		if evidence.ID == selection.EvidenceID && evidence.AssetID == selection.AssetID && evidence.ObservationID == selection.ObservationID && evidence.Kind == model.EvidenceFileSHA256 && evidence.Status == model.EvidenceComplete && evidence.Algorithm == "sha256" && eligibleSubject(evidence.Subject) {
			return observation, evidence, true
		}
	}
	return model.Observation{}, model.ContentEvidence{}, false
}

func eligibleSubject(subject string) bool {
	switch subject {
	case model.EvidenceSubjectManifest, model.EvidenceSubjectSkillDocument, model.EvidenceSubjectShellStartup, model.EvidenceSubjectGitHook, model.EvidenceSubjectLaunchConfig:
		return true
	default:
		return model.ProjectEvidenceSubject(subject)
	}
}

func (m Manager) verifyPreviewSource(ctx context.Context, ref, digest string) (uint32, error) {
	homeRoot, err := openVerifiedAbsoluteRoot(m.Home)
	if err != nil {
		return 0, ErrUnsafeSource
	}
	defer homeRoot.Close()
	components := strings.Split(strings.TrimPrefix(ref, "$HOME/"), "/")
	parent, err := openVerifiedPath(ctx, homeRoot, components[:len(components)-1], false)
	if err != nil {
		return 0, ErrUnsafeSource
	}
	if parent != homeRoot {
		defer parent.Close()
	}
	name := components[len(components)-1]
	expected, err := parent.Lstat(name)
	if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return 0, ErrUnsafeSource
	}
	file, err := parent.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, ErrUnsafeSource
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) || opened.Size() > maxQuarantineBytes {
		return 0, ErrIdentityChanged
	}
	hasher := sha256.New()
	if _, err := copyQuarantine(ctx, hasher, file); err != nil {
		return 0, err
	}
	actual := fmt.Sprintf("%x", hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(digest)) != 1 {
		return 0, ErrDigestMismatch
	}
	return uint32(opened.Mode().Perm()), nil
}

func proposalApproval(p Proposal) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("ssc-init.quarantine.approval.v1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d", p.Action, p.RecordID, p.AssetID, p.ObservationID, p.EvidenceID, p.SHA256, p.OriginalMode)))
	return fmt.Sprintf("approval:sha256:%x", digest)
}
