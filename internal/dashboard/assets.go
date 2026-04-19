package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed assets/*
var assetsFS embed.FS

// staticHandler serves the embedded index.html / app.css / app.js.
// Kept minimal (only three files) and implemented by hand rather than
// mounting http.FS so we can set precise cache headers per asset and
// avoid directory listing surprises.
func (h *Handler) staticHandler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/" {
		p = "/index.html"
	}
	// Route only the known file names. Anything else is 404 — keeps
	// the surface explicit and makes regressions noisy.
	asset := ""
	ctype := ""
	switch p {
	case "/index.html":
		asset, ctype = "assets/index.html", "text/html; charset=utf-8"
	case "/app.css":
		asset, ctype = "assets/app.css", "text/css; charset=utf-8"
	case "/app.js":
		asset, ctype = "assets/app.js", "application/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(assetsFS, asset)
	if err != nil {
		http.Error(w, "asset missing: "+asset, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	// Short cache so browser reloads pick up new builds during
	// operator debugging; real caches happen at the CDN layer in v0.4+.
	w.Header().Set("Cache-Control", "public, max-age=30")
	_, _ = w.Write(data)
}

// assetExists is used by the handler's routing to know if a path maps
// to an embedded asset. Keeps ServeHTTP's switch compact.
func assetExists(p string) bool {
	p = strings.TrimPrefix(path.Clean(p), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	_, err := fs.Stat(assetsFS, "assets/"+p)
	return err == nil
}
