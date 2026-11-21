package dnscert

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// memTXT is a zone held in memory: name -> record id -> value.
type memTXT struct {
	mu      sync.Mutex
	next    int
	records map[string]map[string]string
	deleted chan string
}

func newMemTXT() *memTXT {
	return &memTXT{records: map[string]map[string]string{}, deleted: make(chan string, 16)}
}

func (m *memTXT) SetTXT(_ context.Context, name, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.next++
	id := fmt.Sprintf("rec-%d", m.next)

	if m.records[name] == nil {
		m.records[name] = map[string]string{}
	}

	m.records[name][id] = value

	return id, nil
}

func (m *memTXT) DeleteRecord(_ context.Context, id string) error {
	m.mu.Lock()
	for _, recs := range m.records {
		delete(recs, id)
	}
	m.mu.Unlock()

	m.deleted <- id

	return nil
}

func (m *memTXT) CleanTXT(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.records, name)

	return nil
}

func (m *memTXT) values(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string
	for _, v := range m.records[name] {
		out = append(out, v)
	}

	return out
}

func (m *memTXT) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := 0
	for _, recs := range m.records {
		n += len(recs)
	}

	return n
}

const (
	testZone  = "example.com"
	testFQDN  = "mini.red.z.example.com."
	testValue = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
)

func newTestChallenges(dns TXTProvider) *NodeChallenges {
	n := NewNodeChallenges(testZone, dns)
	n.Wait = func(context.Context, string, string, string) error { return nil }

	return n
}

func TestNodeChallengePublishesOwnName(t *testing.T) {
	zone := newMemTXT()
	n := newTestChallenges(zone)

	// Case and the trailing dot do not change the name.
	err := n.Publish(t.Context(), 1, testFQDN, "TXT", "_acme-challenge.MINI.red.z.example.com.", testValue)
	if err != nil {
		t.Fatalf("own name: %v", err)
	}

	got := zone.values("_acme-challenge.mini.red.z.example.com")
	if len(got) != 1 || got[0] != testValue {
		t.Fatalf("zone holds %v, want [%s]", got, testValue)
	}
}

// A node that could publish another node's challenge would get a public
// certificate for that node's name (KEM-465).
func TestNodeChallengeRefusesAnotherName(t *testing.T) {
	cases := map[string]string{
		"another node":       "_acme-challenge.other.red.z.example.com",
		"the server subzone": "_acme-challenge.z.example.com",
		"the zone apex":      "_acme-challenge.example.com",
		"below its name":     "_acme-challenge.app.mini.red.z.example.com",
		"no challenge label": "mini.red.z.example.com",
		"outside the zone":   "_acme-challenge.mini.red.z.example.org",
	}

	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			zone := newMemTXT()

			err := newTestChallenges(zone).Publish(t.Context(), 1, testFQDN, "TXT", name, testValue)
			if !errors.Is(err, ErrForeignName) {
				t.Fatalf("err = %v, want ErrForeignName", err)
			}

			if zone.total() != 0 {
				t.Fatalf("a refused request wrote %d records", zone.total())
			}
		})
	}
}

// A node whose name falls outside the zone gets nothing, even for its own name.
func TestNodeChallengeRefusesNameOutsideZone(t *testing.T) {
	zone := newMemTXT()

	err := newTestChallenges(zone).Publish(t.Context(), 1, "mini.red.example.org.", "TXT",
		"_acme-challenge.mini.red.example.org", testValue)
	if !errors.Is(err, ErrForeignName) || zone.total() != 0 {
		t.Fatalf("err = %v, records = %d; want ErrForeignName and none", err, zone.total())
	}
}

func TestNodeChallengeAcceptsOnlyACMEValues(t *testing.T) {
	name := "_acme-challenge.mini.red.z.example.com"
	cases := map[string][2]string{
		"record type A":    {"A", testValue},
		"lowercase txt":    {"txt", testValue},
		"free text":        {"TXT", "v=spf1 include:attacker.example -all"},
		"one byte short":   {"TXT", testValue[1:]},
		"one byte long":    {"TXT", testValue + "A"},
		"padded base64":    {"TXT", testValue[:42] + "="},
		"empty value":      {"TXT", ""},
		"value with space": {"TXT", strings.Replace(testValue, "L", " ", 1)},
	}

	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			zone := newMemTXT()

			err := newTestChallenges(zone).Publish(t.Context(), 1, testFQDN, tc[0], name, tc[1])
			if !errors.Is(err, ErrBadChallenge) || zone.total() != 0 {
				t.Fatalf("err = %v, records = %d; want ErrBadChallenge and none", err, zone.total())
			}
		})
	}
}

func TestNodeChallengeIsRateLimitedPerNode(t *testing.T) {
	zone := newMemTXT()
	n := newTestChallenges(zone)
	name := "_acme-challenge.mini.red.z.example.com"

	for i := range nodeChallengeBurst {
		err := n.Publish(t.Context(), 1, testFQDN, "TXT", name, testValue)
		if err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	err := n.Publish(t.Context(), 1, testFQDN, "TXT", name, testValue)
	if !errors.Is(err, ErrTooMany) {
		t.Fatalf("err = %v, want ErrTooMany past the burst", err)
	}

	// Another node keeps its own budget.
	err = n.Publish(t.Context(), 2, "other.red.z.example.com.", "TXT",
		"_acme-challenge.other.red.z.example.com", testValue)
	if err != nil {
		t.Fatalf("other node: %v", err)
	}

	// The refused publish wrote nothing: the burst bounds the live records.
	if got := len(zone.values(name)); got != nodeChallengeBurst {
		t.Fatalf("%d records for %s, want %d", got, name, nodeChallengeBurst)
	}
}

// A wildcard order validates two values on the same name: publishing the
// second must not remove the first before the CA reads it (review, 21/11).
func TestNodeChallengeKeepsEarlierValueOfSameName(t *testing.T) {
	zone := newMemTXT()
	n := newTestChallenges(zone)
	name := "_acme-challenge.mini.red.z.example.com"
	second := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	for _, v := range []string{testValue, second} {
		err := n.Publish(t.Context(), 1, testFQDN, "TXT", name, v)
		if err != nil {
			t.Fatal(err)
		}
	}

	if got := zone.values(name); len(got) != 2 {
		t.Fatalf("zone holds %v, want both values", got)
	}
}

func TestNodeChallengeIsRemovedAfterValidation(t *testing.T) {
	zone := newMemTXT()
	n := newTestChallenges(zone)
	n.RemoveAfter = 10 * time.Millisecond

	err := n.Publish(t.Context(), 1, testFQDN, "TXT", "_acme-challenge.mini.red.z.example.com", testValue)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-zone.deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("the record was never removed")
	}

	if zone.total() != 0 {
		t.Fatalf("%d records left", zone.total())
	}
}

func TestNodeChallengeReportsWhenNotServed(t *testing.T) {
	n := newTestChallenges(newMemTXT())
	n.Wait = func(context.Context, string, string, string) error { return errors.New("not served") }

	err := n.Publish(t.Context(), 1, testFQDN, "TXT", "_acme-challenge.mini.red.z.example.com", testValue)
	if err == nil {
		t.Fatal("a record the CA cannot see yet must not be reported as published")
	}
}
