package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

const planInputVersion uint32 = 1

type planInputBundle struct {
	Version      *uint32                `json:"version"`
	BaseStatus   *syncengine.BaseStatus `json:"base_status"`
	Targets      *[]model.Target        `json:"targets"`
	Base         *[]model.Entry         `json:"base"`
	Observations *[]model.Observation   `json:"observations"`
	Remote       *[]model.Entry         `json:"remote"`
	Coverage     *[]string              `json:"coverage"`
}

type PlanInputError struct {
	Field string
	Kind  string
	Err   error
}

func (e *PlanInputError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("plan input %s field %q", e.Kind, e.Field)
	}
	if e.Kind != "" {
		return "plan input " + e.Kind
	}
	return "invalid plan input"
}

func (e *PlanInputError) Unwrap() error {
	return e.Err
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	exitCode := 0
	root := newPlanCommand(stdout, stderr, &exitCode)
	arguments := append([]string{"plan"}, args...)
	ctx := context.Background()
	if err := root.Run(ctx, arguments); err != nil && exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return exitCode
}

func newPlanCommand(stdout, stderr io.Writer, exitCode *int) *urfave.Command {
	usageHandler := func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
		return urfave.Exit("usage: "+escapePlanField(err.Error()), 2)
	}
	command := &urfave.Command{
		Name: "plan",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "from", Usage: "validated JSON view bundle", OnlyOnce: true},
			&urfave.BoolFlag{Name: "json", Usage: "write the plan as JSON", OnlyOnce: true},
		},
		Action: func(_ context.Context, command *urfave.Command) error {
			if !command.IsSet("from") || command.String("from") == "" {
				return usageExit("dottie plan requires --from <path>")
			}
			preview, err := loadPreview(command.String("from"))
			if err != nil {
				return urfave.Exit(err.Error(), 1)
			}
			var output string
			if command.Bool("json") {
				encoded, err := json.Marshal(preview)
				if err != nil {
					return urfave.Exit("cannot encode plan output", 1)
				}
				output = string(escapeJSONControls(encoded)) + "\n"
			} else {
				output = renderPreview(preview)
			}
			if _, err := io.WriteString(command.Root().Writer, output); err != nil {
				return urfave.Exit("cannot write command output", 1)
			}
			return nil
		},
		Writer:    stdout,
		ErrWriter: stderr,
	}
	command.Suggest = false
	command.DefaultCommand = ""
	command.UseShortOptionHandling = false
	command.EnableShellCompletion = false
	command.ReadArgsFromStdin = false
	command.OnUsageError = usageHandler
	command.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		}
		if code >= 3 || (code != 1 && code != 2) {
			code = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
		*exitCode = code
	}
	return command
}

func loadPreview(path string) (syncengine.Preview, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot read file", Err: err}
	}
	bundle, err := decodePlanInput(data)
	if err != nil {
		return syncengine.Preview{}, err
	}
	bindings := make([]syncengine.TargetBinding, 0, len(*bundle.Targets))
	for _, target := range *bundle.Targets {
		binding, err := syncengine.NewTargetBinding(target)
		if err != nil {
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an invalid target", Err: err}
		}
		bindings = append(bindings, binding)
	}
	local := syncengine.LocalView{Coverage: append([]string(nil), (*bundle.Coverage)...)}
	for _, observation := range *bundle.Observations {
		if err := observation.Validate(); err != nil {
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an invalid observation", Err: err}
		}
		switch observation.State {
		case model.ObservationPresent:
			local.Entries = append(local.Entries, *observation.Entry)
		case model.ObservationMissing:
		case model.ObservationUnknown:
			local.Unknown = append(local.Unknown, observation.Identity)
		case model.ObservationUntracked:
			local.Untracked = append(local.Untracked, observation.Identity)
		default:
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an unsupported observation"}
		}
	}
	plan, err := syncengine.Reconcile(
		syncengine.BaseView{Status: *bundle.BaseStatus, Entries: append([]model.Entry(nil), (*bundle.Base)...)},
		local,
		append([]model.Entry(nil), (*bundle.Remote)...),
		syncengine.Options{Bindings: bindings},
	)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot reconcile supplied views", Err: err}
	}
	preview, err := syncengine.BuildPreview(plan, *bundle.Targets, *bundle.Observations)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot build preview", Err: err}
	}
	return preview, nil
}

func decodePlanInput(data []byte) (planInputBundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle planInputBundle
	if err := decoder.Decode(&bundle); err != nil {
		return planInputBundle{}, &PlanInputError{Kind: "is invalid JSON", Err: err}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return planInputBundle{}, &PlanInputError{Kind: "must contain exactly one JSON value", Err: err}
	}
	if bundle.Version == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "version"}
	}
	if *bundle.Version != planInputVersion {
		return planInputBundle{}, &PlanInputError{Kind: "has unsupported version", Field: "version"}
	}
	if bundle.BaseStatus == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "base_status"}
	}
	if bundle.Targets == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "targets"}
	}
	if bundle.Base == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "base"}
	}
	if bundle.Observations == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "observations"}
	}
	if bundle.Remote == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "remote"}
	}
	if bundle.Coverage == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "coverage"}
	}
	return bundle, nil
}

func renderPreview(preview syncengine.Preview) string {
	var output strings.Builder
	for _, target := range preview.Targets {
		fmt.Fprintf(&output, "target %s\n", escapePlanField(target.ID))
		for _, entry := range target.Entries {
			label := string(entry.Action)
			if label == "" {
				label = string(entry.State)
			}
			if label == "" {
				label = "unchanged"
			}
			fmt.Fprintf(&output, "  %s\t%s\ttransfer-bytes=%d\tsnapshot-bytes=%d", escapePlanField(label), escapePlanField(previewEntryName(entry.Key)), entry.Size, entry.SnapshotBytes)
			if entry.Reason != "" {
				fmt.Fprintf(&output, "\treason=%s", escapePlanField(string(entry.Reason)))
			}
			if entry.Detail != "" {
				fmt.Fprintf(&output, "\tdetail=%s", escapePlanField(entry.Detail))
			}
			if entry.Preimage != nil {
				fmt.Fprintf(&output, "\tpreimage=%s/%04o", escapePlanField(entry.Preimage.Digest), entry.Preimage.Mode)
			}
			if len(entry.Risks) != 0 {
				for _, risk := range entry.Risks {
					fmt.Fprintf(&output, "\trisk=%s", escapePlanField(string(risk)))
				}
			}
			output.WriteByte('\n')
		}
	}
	fmt.Fprintf(&output, "transfer bytes=%d\n", preview.TransferBytes)
	if preview.Complete {
		fmt.Fprintf(&output, "resulting snapshot bytes=%d (complete)\n", preview.ResultingSnapshotBytes)
	} else {
		fmt.Fprintf(&output, "resulting snapshot at least %d bytes, incomplete: %d unresolved\n", preview.ResultingSnapshotBytes, preview.UnresolvedEntries)
	}
	return output.String()
}

func escapePlanField(value string) string {
	var escaped strings.Builder
	for _, r := range value {
		switch {
		case r == 92:
			escaped.WriteRune(r)
			escaped.WriteRune(r)
		case unicode.IsControl(r) && r <= 0xff:
			escaped.WriteByte(92)
			escaped.WriteByte('x')
			fmt.Fprintf(&escaped, "%02X", r)
		case unicode.IsControl(r):
			escaped.WriteByte(92)
			escaped.WriteByte('u')
			fmt.Fprintf(&escaped, "%04X", r)
		default:
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

func escapeJSONControls(encoded []byte) []byte {
	result := make([]byte, 0, len(encoded))
	inString := false
	escaped := false
	for index := 0; index < len(encoded); {
		current := encoded[index]
		if !inString {
			result = append(result, current)
			if current == '"' {
				inString = true
			}
			index++
			continue
		}
		if escaped {
			result = append(result, current)
			escaped = false
			index++
			continue
		}
		if current == 92 {
			result = append(result, current)
			escaped = true
			index++
			continue
		}
		if current == '"' {
			result = append(result, current)
			inString = false
			index++
			continue
		}
		if current >= utf8.RuneSelf {
			r, size := utf8.DecodeRune(encoded[index:])
			if unicode.IsControl(r) {
				result = appendJSONUnicodeEscape(result, r)
				index += size
				continue
			}
			result = append(result, encoded[index:index+size]...)
			index += size
			continue
		}
		result = append(result, current)
		index++
	}
	return result
}

func appendJSONUnicodeEscape(destination []byte, value rune) []byte {
	const digits = "0123456789abcdef"
	destination = append(destination, 92, 'u')
	destination = append(destination,
		digits[(value>>12)&0xf],
		digits[(value>>8)&0xf],
		digits[(value>>4)&0xf],
		digits[value&0xf],
	)
	return destination
}

func previewEntryName(key model.EntryKey) string {
	if key.Source == model.SourceFiles {
		return key.FilePath
	}
	return key.SchemaID + "@" + key.SettingsPath + "/" + key.SettingKey
}
