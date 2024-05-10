package main

import (
	"fmt"
	"net/http"
)

func (cfg *ApiConfig) handlerFileServerRequest(w http.ResponseWriter, r *http.Request) {
	cfg.mutex.Lock()
	defer cfg.mutex.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	w.Write([]byte(fmt.Sprintf(`
<html>

<body>
	<h1>Welcome, Chirpy Admin</h1>
	<p>Chirpy has been visited %d times!</p>
</body>

</html>
	`, cfg.fileserverHits)))
}

func (cfg *ApiConfig) handlerFileServerRequestReset(w http.ResponseWriter, r *http.Request) {
	cfg.mutex.Lock()
	defer cfg.mutex.Unlock()
	cfg.fileserverHits = 0
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
}
