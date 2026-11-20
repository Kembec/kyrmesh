package types

import "testing"

func TestInviteURLCarriesTheKeyInTheQuery(t *testing.T) {
	got := InviteURL("https://net.example/", "hskey-auth-abc-def")
	if want := "https://net.example/join?code=hskey-auth-abc-def"; got != want {
		t.Fatalf("InviteURL = %q, want %q", got, want)
	}
}
