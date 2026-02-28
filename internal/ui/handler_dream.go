package ui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func (s *Server) handleDream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := staticFS.ReadFile("static/dream.html")
	if err != nil {
		http.Error(w, "dream.html not found", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

// dreamEvent is the minimal JSON projection sent to dream mode clients.
type dreamEvent struct {
	ID       int64    `json:"id"`
	TS       string   `json:"ts"`
	Method   string   `json:"method"`
	Host     string   `json:"host"`
	Action   string   `json:"action"`
	Score    int      `json:"score"`
	Signals  []string `json:"signals"`
	BodySize int      `json:"bodySize"`
}

func (s *Server) handleDreamEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.broker.Subscribe()
	defer unsub()

	for {
		select {
		case entry := <-ch:
			var signals []string
			if entry.RiskSignals != "" && entry.RiskSignals != "[]" {
				_ = json.Unmarshal([]byte(entry.RiskSignals), &signals)
			}
			if signals == nil {
				signals = []string{}
			}

			ev := dreamEvent{
				ID:       entry.ID,
				TS:       entry.Timestamp.Format("15:04:05"),
				Method:   entry.Method,
				Host:     entry.Host,
				Action:   entry.Action,
				Score:    entry.RiskScore,
				Signals:  signals,
				BodySize: len(entry.ReqBody),
			}

			data, err := json.Marshal(ev)
			if err != nil {
				log.Printf("dream SSE marshal error: %v", err)
				return
			}

			fmt.Fprintf(w, "event: audit\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
