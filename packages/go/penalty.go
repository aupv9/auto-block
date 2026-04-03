package autoblock

// PenaltyState is the FSM state for a single rate-limit dimension.
type PenaltyState string

const (
	StateClean     PenaltyState = "CLEAN"
	StateWarn      PenaltyState = "WARN"
	StateSlow      PenaltyState = "SLOW"
	StateBlock     PenaltyState = "BLOCK"
	StateBlacklist PenaltyState = "BLACKLIST"
)

func penaltyStateFromString(s string) PenaltyState {
	switch s {
	case "WARN":      return StateWarn
	case "SLOW":      return StateSlow
	case "BLOCK":     return StateBlock
	case "BLACKLIST": return StateBlacklist
	default:          return StateClean
	}
}

func (s PenaltyState) ordinal() int {
	switch s {
	case StateWarn:      return 1
	case StateSlow:      return 2
	case StateBlock:     return 3
	case StateBlacklist: return 4
	default:             return 0
	}
}

func worstState(a, b PenaltyState) PenaltyState {
	if a.ordinal() >= b.ordinal() {
		return a
	}
	return b
}

// Decision is the outcome of evaluating a request against the rate limiter.
type Decision struct {
	Allowed         bool
	State           PenaltyState
	Remaining       int
	DelayMs         int64  // >0 for SLOW state
	RetryAfter      int64  // seconds; populated for BLOCK/BLACKLIST
	StatusCode      int    // 0 = allow, 429 = BLOCK, 403 = BLACKLIST
}

func allowDecision(state PenaltyState, remaining int) Decision {
	d := Decision{Allowed: true, State: state, Remaining: remaining}
	if state == StateSlow {
		d.DelayMs = 3000
	}
	return d
}

func denyDecision(state PenaltyState, retryAfter int64) Decision {
	code := 429
	if state == StateBlacklist {
		code = 403
	}
	return Decision{
		Allowed:    false,
		State:      state,
		StatusCode: code,
		RetryAfter: retryAfter,
	}
}
