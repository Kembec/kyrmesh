package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale/hscontrol/types"
)

// hide_fingerprint removes the routes that name the software and its
// version; without it they answer as upstream does (KEM-460).
func TestHideFingerprintDropsVersionAndSwagger(t *testing.T) {
	for _, hide := range []bool{false, true} {
		app := createTestApp(t, func(cfg *types.Config) { cfg.HideFingerprint = hide })
		t.Cleanup(func() { _ = app.state.Close() })

		router := app.createRouter(grpcRuntime.NewServeMux())

		for _, path := range []string{"/version", "/swagger"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))

			if hide && rec.Code != http.StatusNotFound {
				t.Errorf("hide=true %s: status %d, want 404", path, rec.Code)
			}

			if !hide && rec.Code != http.StatusOK {
				t.Errorf("hide=false %s: status %d, want 200", path, rec.Code)
			}
		}
	}
}
