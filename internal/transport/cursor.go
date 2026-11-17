package transport

import (
	"lamina/internal/engine"
	"lamina/internal/query"
	"lamina/internal/syntax"
	"net/http"
)

type openCursorRequest struct {
	SQL        string         `json:"sql,omitempty"`
	Query      *query.Request `json:"query,omitempty"`
	TTLSeconds int            `json:"ttl_seconds,omitempty"`
}

// openCursor freezes a read query into a pinned-snapshot traversal and
// returns its first page. The request may carry either a structured query or
// a single SQL SELECT, never both.
func (s *Server) openCursor(w http.ResponseWriter, r *http.Request) {
	var in openCursorRequest
	if !decode(w, r, &in) {
		return
	}
	q, err := resolveCursorQuery(in)
	if err != nil {
		respondError(w, err)
		return
	}
	out, err := s.db.OpenCursor(q, in.TTLSeconds)
	if err != nil {
		respondError(w, err)
		return
	}
	write(w, 201, out)
}

func (s *Server) continueCursor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cursor string `json:"cursor"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Cursor == "" {
		respondError(w, &engine.Error{Code: "invalid", Message: "cursor is required"})
		return
	}
	out, err := s.db.ContinueCursor(in.Cursor)
	if err != nil {
		respondError(w, err)
		return
	}
	write(w, 200, out)
}

func (s *Server) closeCursor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cursor string `json:"cursor"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Cursor == "" {
		respondError(w, &engine.Error{Code: "invalid", Message: "cursor is required"})
		return
	}
	if err := s.db.CloseCursor(in.Cursor); err != nil {
		respondError(w, err)
		return
	}
	write(w, 200, map[string]string{"state": "closed"})
}

func resolveCursorQuery(in openCursorRequest) (query.Request, error) {
	if in.SQL != "" && in.Query != nil {
		return query.Request{}, &engine.Error{Code: "invalid", Message: "sql and query are mutually exclusive"}
	}
	if in.SQL != "" {
		q, err := syntax.Parse(in.SQL)
		if err != nil {
			return query.Request{}, &engine.Error{Code: "invalid", Message: err.Error()}
		}
		return q, nil
	}
	if in.Query != nil {
		return *in.Query, nil
	}
	return query.Request{}, &engine.Error{Code: "invalid", Message: "either sql or query is required"}
}
