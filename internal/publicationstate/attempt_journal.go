package publicationstate

func validateAttemptJournalProjection(kinds []string, stored storedAttempt, stage Stage) error {
	if len(kinds) == 0 || kinds[0] != "created" {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	projection := attemptJournalProjection{lifecycle: AttemptPrepared, outcome: OutcomeNotSubmitted}
	for _, kind := range kinds[1:] {
		if projection.retired {
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
		switch kind {
		case "upload-started":
			if projection.lifecycle != AttemptPrepared || projection.outcome != OutcomeNotSubmitted || projection.blocked != "" {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.lifecycle = AttemptUploadStarted
		case "may-have-submitted":
			if projection.lifecycle != AttemptUploadStarted || projection.outcome != OutcomeNotSubmitted || projection.blocked != "" {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.lifecycle = AttemptMayHaveSubmitted
			projection.outcome = OutcomeUnresolved
		case "blocked-floor-replaced":
			if projection.blocked != "" || (projection.lifecycle != AttemptPrepared && projection.lifecycle != AttemptUploadStarted && projection.lifecycle != AttemptMayHaveSubmitted) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.blocked = "blocked-floor-replaced"
		case "outcome-observed-absent-unresolved", "outcome-observed-current", "outcome-committed-superseded", "outcome-lost-fence":
			if projection.lifecycle != AttemptMayHaveSubmitted {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			outcome, valid := attemptOutcomeForEvent(kind)
			if !valid || !attemptOutcomeTransitionAllowed(projection.outcome, outcome) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.outcome = outcome
		case "retired-success":
			if projection.lifecycle != AttemptMayHaveSubmitted || projection.blocked != "" || (projection.outcome != OutcomeUnresolved && projection.outcome != OutcomeAbsentUnresolved && projection.outcome != OutcomeCurrent) {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.lifecycle = AttemptRetiredSuccess
			projection.outcome = OutcomeCurrent
			projection.retired = true
		case "retired-abandoned":
			if projection.lifecycle == AttemptPrepared || projection.lifecycle == AttemptUploadStarted {
				if projection.outcome != OutcomeNotSubmitted {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
			} else if projection.lifecycle == AttemptMayHaveSubmitted {
				if !terminalOutcome(projection.outcome) {
					return classified(ErrSchema, stage, ReasonCorrupt)
				}
			} else {
				return classified(ErrSchema, stage, ReasonCorrupt)
			}
			projection.lifecycle = AttemptRetiredAbandoned
			projection.retired = true
		default:
			return classified(ErrSchema, stage, ReasonCorrupt)
		}
	}
	if projection.lifecycle != stored.lifecycle || projection.outcome != stored.outcome || projection.blocked != stored.blocked {
		return classified(ErrSchema, stage, ReasonCorrupt)
	}
	return nil
}

type attemptJournalProjection struct {
	lifecycle AttemptLifecycle
	outcome   AttemptOutcome
	blocked   string
	retired   bool
}

func attemptOutcomeForEvent(kind string) (AttemptOutcome, bool) {
	switch kind {
	case "outcome-observed-absent-unresolved":
		return OutcomeAbsentUnresolved, true
	case "outcome-observed-current":
		return OutcomeCurrent, true
	case "outcome-committed-superseded":
		return OutcomeSuperseded, true
	case "outcome-lost-fence":
		return OutcomeLostFence, true
	default:
		return "", false
	}
}

func attemptOutcomeTransitionAllowed(previous, next AttemptOutcome) bool {
	if previous == next {
		return false
	}
	switch previous {
	case OutcomeUnresolved, OutcomeAbsentUnresolved:
		return next == OutcomeAbsentUnresolved || next == OutcomeCurrent || next == OutcomeSuperseded || next == OutcomeLostFence
	case OutcomeCurrent:
		return next == OutcomeSuperseded
	default:
		return false
	}
}
