package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/docker/cagent/pkg/session"
	"github.com/docker/cagent/pkg/tools"
)

// PersistentRuntime wraps a Runtime and persists session changes to a store
// based on emitted events. This decouples persistence from the core runtime logic.
type PersistentRuntime struct {
	inner Runtime
	store session.Store
}

// streamingState tracks the accumulated content for a streaming assistant message
type streamingState struct {
	content          strings.Builder
	reasoningContent strings.Builder
	agentName        string
}

// NewPersistentRuntime creates a runtime that automatically persists session changes.
func NewPersistentRuntime(inner Runtime, store session.Store) *PersistentRuntime {
	return &PersistentRuntime{
		inner: inner,
		store: store,
	}
}

// RunStream wraps the inner runtime's RunStream and intercepts events
// to persist session changes to the store.
func (r *PersistentRuntime) RunStream(ctx context.Context, sess *session.Session) <-chan Event {
	// Ensure session exists in store (upsert) for root sessions only
	if !sess.IsSubSession() {
		if err := r.store.UpdateSession(ctx, sess); err != nil {
			slog.Warn("Failed to persist initial session", "session_id", sess.ID, "error", err)
		}
	}

	innerEvents := r.inner.RunStream(ctx, sess)
	events := make(chan Event, 128)

	go func() {
		defer close(events)

		// Track streaming state for this stream
		streaming := &streamingState{}

		for event := range innerEvents {
			// Handle persistence based on event type
			r.handleEvent(ctx, sess, event, streaming)

			// Forward event to consumer
			events <- event
		}
	}()

	return events
}

func (r *PersistentRuntime) handleEvent(ctx context.Context, sess *session.Session, event Event, streaming *streamingState) {
	// Skip persistence for sub-sessions (they're persisted when added to parent)
	if sess.IsSubSession() {
		return
	}

	switch e := event.(type) {
	case *AgentChoiceEvent:
		// Accumulate streaming content and persist
		streaming.content.WriteString(e.Content)
		streaming.agentName = e.AgentName
		if err := r.store.UpsertStreamingAssistantMessage(ctx, sess.ID, e.AgentName, streaming.content.String(), streaming.reasoningContent.String()); err != nil {
			slog.Warn("Failed to persist streaming content", "session_id", sess.ID, "error", err)
		}

	case *AgentChoiceReasoningEvent:
		// Accumulate streaming reasoning content and persist
		streaming.reasoningContent.WriteString(e.Content)
		streaming.agentName = e.AgentName
		if err := r.store.UpsertStreamingAssistantMessage(ctx, sess.ID, e.AgentName, streaming.content.String(), streaming.reasoningContent.String()); err != nil {
			slog.Warn("Failed to persist streaming reasoning content", "session_id", sess.ID, "error", err)
		}

	case *MessageAddedEvent:
		// Reset streaming state when a complete message is added
		streaming.content.Reset()
		streaming.reasoningContent.Reset()
		streaming.agentName = ""

		if msg, ok := e.Message.(*session.Message); ok {
			if err := r.store.AddMessage(ctx, e.SessionID, msg); err != nil {
				slog.Warn("Failed to persist message", "session_id", e.SessionID, "error", err)
			}
		}

	case *SubSessionCompletedEvent:
		if subSess, ok := e.SubSession.(*session.Session); ok {
			if err := r.store.AddSubSession(ctx, e.ParentSessionID, subSess); err != nil {
				slog.Warn("Failed to persist sub-session", "parent_id", e.ParentSessionID, "error", err)
			}
		}

	case *SummaryAddedEvent:
		if err := r.store.AddSummary(ctx, e.SessionID, e.Summary); err != nil {
			slog.Warn("Failed to persist summary", "session_id", e.SessionID, "error", err)
		}

	case *TokenUsageEvent:
		if e.Usage != nil {
			if err := r.store.UpdateSessionTokens(ctx, sess.ID, e.Usage.InputTokens, e.Usage.OutputTokens, e.Usage.Cost); err != nil {
				slog.Warn("Failed to persist token usage", "session_id", sess.ID, "error", err)
			}
		}

	case *SessionTitleEvent:
		if err := r.store.UpdateSessionTitle(ctx, sess.ID, e.Title); err != nil {
			slog.Warn("Failed to persist session title", "session_id", sess.ID, "error", err)
		}
	}
}

// Run wraps the inner runtime's Run method
func (r *PersistentRuntime) Run(ctx context.Context, sess *session.Session) ([]session.Message, error) {
	eventsChan := r.RunStream(ctx, sess)

	for event := range eventsChan {
		if errEvent, ok := event.(*ErrorEvent); ok {
			return nil, fmt.Errorf("%s", errEvent.Error)
		}
	}

	return sess.GetAllMessages(), nil
}

// Delegate all other Runtime interface methods to inner runtime

func (r *PersistentRuntime) CurrentAgentInfo(ctx context.Context) CurrentAgentInfo {
	return r.inner.CurrentAgentInfo(ctx)
}

func (r *PersistentRuntime) CurrentAgentName() string {
	return r.inner.CurrentAgentName()
}

func (r *PersistentRuntime) SetCurrentAgent(agentName string) error {
	return r.inner.SetCurrentAgent(agentName)
}

func (r *PersistentRuntime) CurrentAgentTools(ctx context.Context) ([]tools.Tool, error) {
	return r.inner.CurrentAgentTools(ctx)
}

func (r *PersistentRuntime) EmitStartupInfo(ctx context.Context, events chan Event) {
	r.inner.EmitStartupInfo(ctx, events)
}

func (r *PersistentRuntime) ResetStartupInfo() {
	r.inner.ResetStartupInfo()
}

func (r *PersistentRuntime) Resume(ctx context.Context, req ResumeRequest) {
	r.inner.Resume(ctx, req)
}

func (r *PersistentRuntime) ResumeElicitation(ctx context.Context, action tools.ElicitationAction, content map[string]any) error {
	return r.inner.ResumeElicitation(ctx, action, content)
}

func (r *PersistentRuntime) SessionStore() session.Store {
	return r.store
}

func (r *PersistentRuntime) Summarize(ctx context.Context, sess *session.Session, additionalPrompt string, events chan Event) {
	r.inner.Summarize(ctx, sess, additionalPrompt, events)
}

// InnerRuntime returns the wrapped runtime for cases where access to
// LocalRuntime-specific methods is needed (e.g., RAG initialization).
func (r *PersistentRuntime) InnerRuntime() Runtime {
	return r.inner
}

// SetAgentModel delegates to the inner runtime if it implements ModelSwitcher.
func (r *PersistentRuntime) SetAgentModel(ctx context.Context, agentName, modelRef string) error {
	if ms, ok := r.inner.(ModelSwitcher); ok {
		return ms.SetAgentModel(ctx, agentName, modelRef)
	}
	return nil
}

// AvailableModels delegates to the inner runtime if it implements ModelSwitcher.
func (r *PersistentRuntime) AvailableModels(ctx context.Context) []ModelChoice {
	if ms, ok := r.inner.(ModelSwitcher); ok {
		return ms.AvailableModels(ctx)
	}
	return nil
}

// Ensure PersistentRuntime implements ModelSwitcher
var _ ModelSwitcher = (*PersistentRuntime)(nil)
