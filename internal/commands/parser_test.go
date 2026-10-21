package commands

import (
	"errors"
	"testing"
	"time"
)

func TestParseQuiet(t *testing.T) {
	cases := []struct {
		input    string
		wantKind Kind
		wantDur  time.Duration
		wantErr  bool
	}{
		{"/quiet 2h suspicious login", KindQuiet, 2 * time.Hour, false},
		{"/quiet 1d maintenance window", KindQuiet, 24 * time.Hour, false},
		{"/quiet 2w planned patching", KindQuiet, 14 * 24 * time.Hour, false},
		{"/quiet 1mo rotation cycle", KindQuiet, 30 * 24 * time.Hour, false},
		{"/quiet 30m quick suppression", KindQuiet, 30 * time.Minute, false},
		{"/quiet -1h bad", KindQuiet, 0, true},   // negative
		{"/quiet nodur", KindQuiet, 0, true},      // missing reason
		{"/quiet  nodur", KindQuiet, 0, true},     // missing reason after space
	}

	for _, tc := range cases {
		cmd, err := Parse(tc.input)
		if tc.wantErr {
			if err == nil || errors.Is(err, ErrNoCommand) {
				t.Errorf("input %q: expected parse error, got cmd=%v err=%v", tc.input, cmd, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("input %q: unexpected error: %v", tc.input, err)
			continue
		}
		if cmd.Kind != tc.wantKind {
			t.Errorf("input %q: kind %q want %q", tc.input, cmd.Kind, tc.wantKind)
		}
		if cmd.Duration != tc.wantDur {
			t.Errorf("input %q: duration %v want %v", tc.input, cmd.Duration, tc.wantDur)
		}
	}
}

func TestParseUnquiet(t *testing.T) {
	cmd, err := Parse("/unquiet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Kind != KindUnquiet {
		t.Fatalf("want unquiet, got %q", cmd.Kind)
	}
}

func TestParseBenign(t *testing.T) {
	cmd, err := Parse("/benign this is a routine nightly backup")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Kind != KindBenign {
		t.Fatalf("want benign, got %q", cmd.Kind)
	}
	if cmd.Reason == "" {
		t.Fatal("reason should not be empty")
	}
}

func TestParseBenignMissingReason(t *testing.T) {
	// "/benign " with no reason text: trailing space is stripped, leaving "/benign"
	// which doesn't match the "/benign " prefix — returns ErrNoCommand (no command found).
	// Either ErrNoCommand or a "missing reason" error is acceptable; nil is not.
	_, err := Parse("/benign ")
	if err == nil {
		t.Fatal("expected error for missing reason, got nil")
	}
}

func TestParseNoCommand(t *testing.T) {
	inputs := []string{
		"",
		"just a normal reply",
		"no slash here",
		"/unknown-command foo",
	}
	for _, s := range inputs {
		_, err := Parse(s)
		if !errors.Is(err, ErrNoCommand) {
			t.Errorf("input %q: want ErrNoCommand, got %v", s, err)
		}
	}
}

func TestParseFirstCommandWins(t *testing.T) {
	text := "Some text\n/quiet 1h first command\n/unquiet\n"
	cmd, err := Parse(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Kind != KindQuiet {
		t.Fatalf("want first command (quiet), got %q", cmd.Kind)
	}
}

func TestParseCommandNotInMiddleOfLine(t *testing.T) {
	// A /command that is not at the start of a line must be ignored.
	text := "some text /quiet 1h embedded"
	_, err := Parse(text)
	if !errors.Is(err, ErrNoCommand) {
		t.Errorf("embedded /command should not match, got err=%v", err)
	}
}
