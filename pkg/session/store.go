package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/docker/cagent/pkg/chat"
	"github.com/docker/cagent/pkg/concurrent"
	"github.com/docker/cagent/pkg/sqliteutil"
)

var (
	ErrEmptyID  = errors.New("session ID cannot be empty")
	ErrNotFound = errors.New("session not found")
)

// Summary contains lightweight session metadata for listing purposes.
// This is used instead of loading full Session objects with all messages.
type Summary struct {
	ID        string
	Title     string
	CreatedAt time.Time
	Starred   bool
}

// Store defines the interface for session storage
type Store interface {
	// === Core session operations ===
	AddSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessions(ctx context.Context) ([]*Session, error)
	GetSessionSummaries(ctx context.Context) ([]Summary, error)
	DeleteSession(ctx context.Context, id string) error
	UpdateSession(ctx context.Context, session *Session) error // Updates metadata only (not messages/items)
	SetSessionStarred(ctx context.Context, id string, starred bool) error

	// === Granular item operations ===

	// AddMessage adds a message to a session at the next position
	AddMessage(ctx context.Context, sessionID string, msg *Message) error

	// AddSubSession creates a sub-session and links it to the parent.
	// The sub-session is stored as a separate session row with parent_id set.
	AddSubSession(ctx context.Context, parentSessionID string, subSession *Session) error

	// AddSummary adds a summary item to a session at the next position
	AddSummary(ctx context.Context, sessionID, summary string) error

	// === Streaming assistant message operations ===

	// UpsertStreamingAssistantMessage creates or updates a streaming assistant message.
	// This is used to persist the message content as tokens arrive during streaming.
	// The message is identified by sessionID and agentName (there can only be one active
	// streaming message per session/agent at a time).
	UpsertStreamingAssistantMessage(ctx context.Context, sessionID, agentName, content, reasoningContent string) error

	// === Granular metadata updates ===

	// UpdateSessionTokens updates only token/cost fields
	UpdateSessionTokens(ctx context.Context, sessionID string, inputTokens, outputTokens int64, cost float64) error

	// UpdateSessionTitle updates only the title
	UpdateSessionTitle(ctx context.Context, sessionID, title string) error

	// UpdateSessionFlags updates tools_approved and thinking flags
	UpdateSessionFlags(ctx context.Context, sessionID string, toolsApproved, thinking bool) error
}

type InMemorySessionStore struct {
	sessions *concurrent.Map[string, *Session]
}

func NewInMemorySessionStore() Store {
	return &InMemorySessionStore{
		sessions: concurrent.NewMap[string, *Session](),
	}
}

func (s *InMemorySessionStore) AddSession(_ context.Context, session *Session) error {
	if session.ID == "" {
		return ErrEmptyID
	}
	s.sessions.Store(session.ID, session)
	return nil
}

func (s *InMemorySessionStore) GetSession(_ context.Context, id string) (*Session, error) {
	if id == "" {
		return nil, ErrEmptyID
	}
	session, exists := s.sessions.Load(id)
	if !exists {
		return nil, ErrNotFound
	}
	return session, nil
}

func (s *InMemorySessionStore) GetSessions(_ context.Context) ([]*Session, error) {
	sessions := make([]*Session, 0, s.sessions.Length())
	s.sessions.Range(func(key string, value *Session) bool {
		sessions = append(sessions, value)
		return true
	})
	return sessions, nil
}

func (s *InMemorySessionStore) GetSessionSummaries(_ context.Context) ([]Summary, error) {
	summaries := make([]Summary, 0, s.sessions.Length())
	s.sessions.Range(func(_ string, value *Session) bool {
		summaries = append(summaries, Summary{
			ID:        value.ID,
			Title:     value.Title,
			CreatedAt: value.CreatedAt,
			Starred:   value.Starred,
		})
		return true
	})
	return summaries, nil
}

func (s *InMemorySessionStore) DeleteSession(_ context.Context, id string) error {
	if id == "" {
		return ErrEmptyID
	}
	_, exists := s.sessions.Load(id)
	if !exists {
		return ErrNotFound
	}
	s.sessions.Delete(id)
	return nil
}

// UpdateSession updates an existing session, or creates it if it doesn't exist (upsert).
// This enables lazy session persistence - sessions are only stored when they have content.
func (s *InMemorySessionStore) UpdateSession(_ context.Context, session *Session) error {
	if session.ID == "" {
		return ErrEmptyID
	}
	s.sessions.Store(session.ID, session)
	return nil
}

// SetSessionStarred sets the starred status of a session.
func (s *InMemorySessionStore) SetSessionStarred(_ context.Context, id string, starred bool) error {
	if id == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(id)
	if !exists {
		return ErrNotFound
	}
	session.Starred = starred
	s.sessions.Store(id, session)
	return nil
}

// AddMessage adds a message to a session at the next position.
func (s *InMemorySessionStore) AddMessage(_ context.Context, sessionID string, msg *Message) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}
	session.AddMessage(msg)
	return nil
}

// AddSubSession creates a sub-session and links it to the parent.
func (s *InMemorySessionStore) AddSubSession(_ context.Context, parentSessionID string, subSession *Session) error {
	if parentSessionID == "" {
		return ErrEmptyID
	}
	parent, exists := s.sessions.Load(parentSessionID)
	if !exists {
		return ErrNotFound
	}
	subSession.ParentID = parentSessionID
	s.sessions.Store(subSession.ID, subSession)
	parent.AddSubSession(subSession)
	return nil
}

// AddSummary adds a summary item to a session at the next position.
func (s *InMemorySessionStore) AddSummary(_ context.Context, sessionID, summary string) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}
	session.Messages = append(session.Messages, Item{Summary: summary})
	return nil
}

// UpdateSessionTokens updates only token/cost fields.
func (s *InMemorySessionStore) UpdateSessionTokens(_ context.Context, sessionID string, inputTokens, outputTokens int64, cost float64) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}
	session.InputTokens = inputTokens
	session.OutputTokens = outputTokens
	session.Cost = cost
	return nil
}

// UpdateSessionTitle updates only the title.
func (s *InMemorySessionStore) UpdateSessionTitle(_ context.Context, sessionID, title string) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}
	session.Title = title
	return nil
}

// UpdateSessionFlags updates tools_approved and thinking flags.
func (s *InMemorySessionStore) UpdateSessionFlags(_ context.Context, sessionID string, toolsApproved, thinking bool) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}
	session.ToolsApproved = toolsApproved
	session.Thinking = thinking
	return nil
}

// UpsertStreamingAssistantMessage creates or updates a streaming assistant message in memory.
func (s *InMemorySessionStore) UpsertStreamingAssistantMessage(_ context.Context, sessionID, agentName, content, reasoningContent string) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	session, exists := s.sessions.Load(sessionID)
	if !exists {
		return ErrNotFound
	}

	// Find the last assistant message from this agent, or create a new one
	for i := len(session.Messages) - 1; i >= 0; i-- {
		item := &session.Messages[i]
		if item.IsMessage() && item.Message.Message.Role == chat.MessageRoleAssistant && item.Message.AgentName == agentName {
			// Update existing message
			item.Message.Message.Content = content
			item.Message.Message.ReasoningContent = reasoningContent
			return nil
		}
	}

	// No existing assistant message from this agent, create a new one
	session.Messages = append(session.Messages, Item{
		Message: &Message{
			AgentName: agentName,
			Message: chat.Message{
				Role:             chat.MessageRoleAssistant,
				Content:          content,
				ReasoningContent: reasoningContent,
			},
		},
	})
	return nil
}

// SQLiteSessionStore implements Store using SQLite
type SQLiteSessionStore struct {
	db *sql.DB
}

// NewSQLiteSessionStore creates a new SQLite session store
func NewSQLiteSessionStore(path string) (Store, error) {
	db, err := sqliteutil.OpenDB(path)
	if err != nil {
		return nil, err
	}

	_, err = db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			messages TEXT,
			created_at TEXT
		)
	`)
	if err != nil {
		db.Close()
		if sqliteutil.IsCantOpenError(err) {
			return nil, sqliteutil.DiagnoseDBOpenError(path, err)
		}
		return nil, err
	}

	// Initialize and run migrations
	migrationManager := NewMigrationManager(db)
	err = migrationManager.InitializeMigrations(context.Background())
	if err != nil {
		return nil, err
	}

	return &SQLiteSessionStore{db: db}, nil
}

// AddSession adds a new session to the store, including any messages
func (s *SQLiteSessionStore) AddSession(ctx context.Context, session *Session) error {
	if session.ID == "" {
		return ErrEmptyID
	}

	permissionsJSON := ""
	if session.Permissions != nil {
		permBytes, err := json.Marshal(session.Permissions)
		if err != nil {
			return err
		}
		permissionsJSON = string(permBytes)
	}

	// Marshal agent model overrides (default to empty object if nil)
	agentModelOverridesJSON := "{}"
	if len(session.AgentModelOverrides) > 0 {
		overridesBytes, err := json.Marshal(session.AgentModelOverrides)
		if err != nil {
			return err
		}
		agentModelOverridesJSON = string(overridesBytes)
	}

	// Marshal custom models used (default to empty array if nil)
	customModelsUsedJSON := "[]"
	if len(session.CustomModelsUsed) > 0 {
		customBytes, err := json.Marshal(session.CustomModelsUsed)
		if err != nil {
			return err
		}
		customModelsUsedJSON = string(customBytes)
	}

	// Use NULL for empty parent_id to avoid foreign key constraint issues
	var parentID any
	if session.ParentID != "" {
		parentID = session.ParentID
	}

	// Use a transaction to insert session and its items
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO sessions (id, tools_approved, input_tokens, output_tokens, title, send_user_message, max_iterations, working_dir, created_at, permissions, agent_model_overrides, custom_models_used, thinking, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		session.ID, session.ToolsApproved, session.InputTokens, session.OutputTokens, session.Title, session.SendUserMessage, session.MaxIterations, session.WorkingDir, session.CreatedAt.Format(time.RFC3339), permissionsJSON, agentModelOverridesJSON, customModelsUsedJSON, session.Thinking, parentID)
	if err != nil {
		return err
	}

	// Insert all messages into session_items
	for position, item := range session.Messages {
		if err := s.addItemTx(ctx, tx, session.ID, position, item); err != nil {
			return fmt.Errorf("adding item at position %d: %w", position, err)
		}
	}

	return tx.Commit()
}

// scanSession scans a single row into a Session struct
// Note: Messages are loaded separately from session_items table
func scanSession(scanner interface {
	Scan(dest ...any) error
},
) (*Session, error) {
	var toolsApprovedStr, inputTokensStr, outputTokensStr, titleStr, costStr, sendUserMessageStr, maxIterationsStr, createdAtStr, starredStr, agentModelOverridesJSON, customModelsUsedJSON, thinkingStr string
	var sessionID string
	var workingDir sql.NullString
	var permissionsJSON sql.NullString
	var parentID sql.NullString

	err := scanner.Scan(&sessionID, &toolsApprovedStr, &inputTokensStr, &outputTokensStr, &titleStr, &costStr, &sendUserMessageStr, &maxIterationsStr, &workingDir, &createdAtStr, &starredStr, &permissionsJSON, &agentModelOverridesJSON, &customModelsUsedJSON, &thinkingStr, &parentID)
	if err != nil {
		return nil, err
	}

	toolsApproved, err := strconv.ParseBool(toolsApprovedStr)
	if err != nil {
		return nil, err
	}

	inputTokens, err := strconv.ParseInt(inputTokensStr, 10, 64)
	if err != nil {
		return nil, err
	}

	outputTokens, err := strconv.ParseInt(outputTokensStr, 10, 64)
	if err != nil {
		return nil, err
	}

	cost, err := strconv.ParseFloat(costStr, 64)
	if err != nil {
		return nil, err
	}

	sendUserMessage, err := strconv.ParseBool(sendUserMessageStr)
	if err != nil {
		return nil, err
	}

	maxIterations, err := strconv.Atoi(maxIterationsStr)
	if err != nil {
		return nil, err
	}

	createdAt, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, err
	}

	starred, err := strconv.ParseBool(starredStr)
	if err != nil {
		return nil, err
	}

	thinking, err := strconv.ParseBool(thinkingStr)
	if err != nil {
		return nil, err
	}

	// Parse permissions if present
	var permissions *PermissionsConfig
	if permissionsJSON.Valid && permissionsJSON.String != "" {
		permissions = &PermissionsConfig{}
		if err := json.Unmarshal([]byte(permissionsJSON.String), permissions); err != nil {
			return nil, err
		}
	}

	// Parse agent model overrides (may be empty or "{}")
	var agentModelOverrides map[string]string
	if agentModelOverridesJSON != "" && agentModelOverridesJSON != "{}" {
		if err := json.Unmarshal([]byte(agentModelOverridesJSON), &agentModelOverrides); err != nil {
			return nil, err
		}
	}

	// Parse custom models used (may be empty or "[]")
	var customModelsUsed []string
	if customModelsUsedJSON != "" && customModelsUsedJSON != "[]" {
		if err := json.Unmarshal([]byte(customModelsUsedJSON), &customModelsUsed); err != nil {
			return nil, err
		}
	}

	return &Session{
		ID:                  sessionID,
		Title:               titleStr,
		Messages:            nil, // Loaded separately from session_items
		ToolsApproved:       toolsApproved,
		Thinking:            thinking,
		InputTokens:         inputTokens,
		OutputTokens:        outputTokens,
		Cost:                cost,
		SendUserMessage:     sendUserMessage,
		MaxIterations:       maxIterations,
		CreatedAt:           createdAt,
		WorkingDir:          workingDir.String,
		Starred:             starred,
		Permissions:         permissions,
		AgentModelOverrides: agentModelOverrides,
		CustomModelsUsed:    customModelsUsed,
		ParentID:            parentID.String,
	}, nil
}

// GetSession retrieves a session by ID
func (s *SQLiteSessionStore) GetSession(ctx context.Context, id string) (*Session, error) {
	if id == "" {
		return nil, ErrEmptyID
	}

	row := s.db.QueryRowContext(ctx,
		"SELECT id, tools_approved, input_tokens, output_tokens, title, cost, send_user_message, max_iterations, working_dir, created_at, starred, permissions, agent_model_overrides, custom_models_used, thinking, parent_id FROM sessions WHERE id = ?", id)

	sess, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Load messages from session_items table
	items, err := s.loadSessionItems(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("loading session items: %w", err)
	}
	sess.Messages = items

	return sess, nil
}

// sessionItemRow holds the raw data from a session_items row
type sessionItemRow struct {
	position     int
	itemType     string
	agentName    sql.NullString
	messageJSON  sql.NullString
	implicit     bool
	subsessionID sql.NullString
	summaryText  sql.NullString
}

// loadSessionItems loads all items for a session from the session_items table
func (s *SQLiteSessionStore) loadSessionItems(ctx context.Context, sessionID string) ([]Item, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT position, item_type, agent_name, message_json, implicit, subsession_id, summary_text
		 FROM session_items WHERE session_id = ? ORDER BY position`, sessionID)
	if err != nil {
		return nil, err
	}

	// First, collect all raw row data so we can close the result set
	// before making any recursive calls (SQLite doesn't allow concurrent queries)
	var rawRows []sessionItemRow
	for rows.Next() {
		var row sessionItemRow
		if err := rows.Scan(&row.position, &row.itemType, &row.agentName, &row.messageJSON, &row.implicit, &row.subsessionID, &row.summaryText); err != nil {
			rows.Close()
			return nil, err
		}
		rawRows = append(rawRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Now process the collected rows, making recursive calls as needed
	var items []Item
	for _, row := range rawRows {
		switch row.itemType {
		case "message":
			var chatMsg chat.Message
			if err := json.Unmarshal([]byte(row.messageJSON.String), &chatMsg); err != nil {
				return nil, fmt.Errorf("unmarshaling message at position %d: %w", row.position, err)
			}
			items = append(items, Item{
				Message: &Message{
					AgentName: row.agentName.String,
					Message:   chatMsg,
					Implicit:  row.implicit,
				},
			})

		case "subsession":
			// Recursively get sub-session (safe now that rows is closed)
			subSession, err := s.GetSession(ctx, row.subsessionID.String)
			if err != nil {
				return nil, fmt.Errorf("getting sub-session %s: %w", row.subsessionID.String, err)
			}
			items = append(items, Item{SubSession: subSession})

		case "summary":
			items = append(items, Item{Summary: row.summaryText.String})
		}
	}

	return items, nil
}

// GetSessions retrieves all root sessions (excludes sub-sessions)
func (s *SQLiteSessionStore) GetSessions(ctx context.Context) ([]*Session, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, tools_approved, input_tokens, output_tokens, title, cost, send_user_message, max_iterations, working_dir, created_at, starred, permissions, agent_model_overrides, custom_models_used, thinking, parent_id FROM sessions WHERE parent_id IS NULL OR parent_id = '' ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// GetSessionSummaries retrieves lightweight session metadata for listing (excludes sub-sessions).
// This is much faster than GetSessions as it doesn't load message content.
func (s *SQLiteSessionStore) GetSessionSummaries(ctx context.Context) ([]Summary, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, title, created_at, starred FROM sessions WHERE parent_id IS NULL OR parent_id = '' ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []Summary
	for rows.Next() {
		var id, title, createdAtStr, starredStr string
		if err := rows.Scan(&id, &title, &createdAtStr, &starredStr); err != nil {
			return nil, err
		}
		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return nil, err
		}
		starred, err := strconv.ParseBool(starredStr)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, Summary{
			ID:        id,
			Title:     title,
			CreatedAt: createdAt,
			Starred:   starred,
		})
	}

	return summaries, nil
}

// DeleteSession deletes a session by ID
func (s *SQLiteSessionStore) DeleteSession(ctx context.Context, id string) error {
	if id == "" {
		return ErrEmptyID
	}

	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateSession updates an existing session's metadata, or creates it if it doesn't exist (upsert).
// This method only updates metadata columns, NOT messages/items which are managed via
// AddMessage, AddSubSession, and AddSummary methods.
// This enables lazy session persistence - sessions are only stored when they have content.
func (s *SQLiteSessionStore) UpdateSession(ctx context.Context, session *Session) error {
	if session.ID == "" {
		return ErrEmptyID
	}

	permissionsJSON := ""
	if session.Permissions != nil {
		permBytes, err := json.Marshal(session.Permissions)
		if err != nil {
			return err
		}
		permissionsJSON = string(permBytes)
	}

	// Marshal agent model overrides (default to empty object if nil)
	agentModelOverridesJSON := "{}"
	if len(session.AgentModelOverrides) > 0 {
		overridesBytes, err := json.Marshal(session.AgentModelOverrides)
		if err != nil {
			return err
		}
		agentModelOverridesJSON = string(overridesBytes)
	}

	// Marshal custom models used (default to empty array if nil)
	customModelsUsedJSON := "[]"
	if len(session.CustomModelsUsed) > 0 {
		customBytes, err := json.Marshal(session.CustomModelsUsed)
		if err != nil {
			return err
		}
		customModelsUsedJSON = string(customBytes)
	}

	// Use NULL for empty parent_id to avoid foreign key constraint issues
	var parentID any
	if session.ParentID != "" {
		parentID = session.ParentID
	}

	// Use INSERT OR REPLACE for upsert behavior - creates if not exists, updates if exists
	// Messages are managed separately via AddMessage, AddSubSession, AddSummary methods
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, tools_approved, input_tokens, output_tokens, title, cost, send_user_message, max_iterations, working_dir, created_at, starred, permissions, agent_model_overrides, custom_models_used, thinking, parent_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   title = excluded.title,
		   tools_approved = excluded.tools_approved,
		   input_tokens = excluded.input_tokens,
		   output_tokens = excluded.output_tokens,
		   cost = excluded.cost,
		   send_user_message = excluded.send_user_message,
		   max_iterations = excluded.max_iterations,
		   working_dir = excluded.working_dir,
		   starred = excluded.starred,
		   permissions = excluded.permissions,
		   agent_model_overrides = excluded.agent_model_overrides,
		   custom_models_used = excluded.custom_models_used,
		   thinking = excluded.thinking,
		   parent_id = excluded.parent_id`,
		session.ID, session.ToolsApproved, session.InputTokens, session.OutputTokens,
		session.Title, session.Cost, session.SendUserMessage, session.MaxIterations, session.WorkingDir,
		session.CreatedAt.Format(time.RFC3339), session.Starred, permissionsJSON, agentModelOverridesJSON, customModelsUsedJSON, session.Thinking, parentID)
	return err
}

// SetSessionStarred sets the starred status of a session.
func (s *SQLiteSessionStore) SetSessionStarred(ctx context.Context, id string, starred bool) error {
	if id == "" {
		return ErrEmptyID
	}

	result, err := s.db.ExecContext(ctx, "UPDATE sessions SET starred = ? WHERE id = ?", starred, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Close closes the database connection
func (s *SQLiteSessionStore) Close() error {
	return s.db.Close()
}

// AddMessage adds a message to a session at the next position.
func (s *SQLiteSessionStore) AddMessage(ctx context.Context, sessionID string, msg *Message) error {
	if sessionID == "" {
		return ErrEmptyID
	}

	msgJSON, err := json.Marshal(msg.Message)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	// Get next position using subquery for atomicity
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO session_items (session_id, position, item_type, agent_name, message_json, implicit)
		 VALUES (?, (SELECT COALESCE(MAX(position), -1) + 1 FROM session_items WHERE session_id = ?), 'message', ?, ?, ?)`,
		sessionID, sessionID, msg.AgentName, string(msgJSON), msg.Implicit)
	return err
}

// AddSubSession creates a sub-session and links it to the parent.
func (s *SQLiteSessionStore) AddSubSession(ctx context.Context, parentSessionID string, subSession *Session) error {
	if parentSessionID == "" || subSession.ID == "" {
		return ErrEmptyID
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 1. Set parent_id on sub-session
	subSession.ParentID = parentSessionID

	// 2. Insert sub-session as a new session row
	if err := s.addSessionTx(ctx, tx, subSession); err != nil {
		return fmt.Errorf("inserting sub-session: %w", err)
	}

	// 3. Recursively add all items from the sub-session
	for i, item := range subSession.Messages {
		if err := s.addItemTx(ctx, tx, subSession.ID, i, item); err != nil {
			return fmt.Errorf("inserting sub-session item %d: %w", i, err)
		}
	}

	// 4. Add reference in parent's items
	_, err = tx.ExecContext(ctx,
		`INSERT INTO session_items (session_id, position, item_type, subsession_id)
		 VALUES (?, (SELECT COALESCE(MAX(position), -1) + 1 FROM session_items WHERE session_id = ?), 'subsession', ?)`,
		parentSessionID, parentSessionID, subSession.ID)
	if err != nil {
		return fmt.Errorf("inserting subsession reference: %w", err)
	}

	return tx.Commit()
}

// addSessionTx inserts a session within a transaction.
func (s *SQLiteSessionStore) addSessionTx(ctx context.Context, tx *sql.Tx, session *Session) error {
	permissionsJSON := ""
	if session.Permissions != nil {
		permBytes, err := json.Marshal(session.Permissions)
		if err != nil {
			return err
		}
		permissionsJSON = string(permBytes)
	}

	agentModelOverridesJSON := "{}"
	if len(session.AgentModelOverrides) > 0 {
		overridesBytes, err := json.Marshal(session.AgentModelOverrides)
		if err != nil {
			return err
		}
		agentModelOverridesJSON = string(overridesBytes)
	}

	customModelsUsedJSON := "[]"
	if len(session.CustomModelsUsed) > 0 {
		customBytes, err := json.Marshal(session.CustomModelsUsed)
		if err != nil {
			return err
		}
		customModelsUsedJSON = string(customBytes)
	}

	// Use NULL for empty parent_id to avoid foreign key constraint issues
	var parentID any
	if session.ParentID != "" {
		parentID = session.ParentID
	}

	_, err := tx.ExecContext(ctx,
		`INSERT INTO sessions (id, tools_approved, input_tokens, output_tokens, title, cost, send_user_message, max_iterations, working_dir, created_at, starred, permissions, agent_model_overrides, custom_models_used, thinking, parent_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.ToolsApproved, session.InputTokens, session.OutputTokens,
		session.Title, session.Cost, session.SendUserMessage, session.MaxIterations,
		session.WorkingDir, session.CreatedAt.Format(time.RFC3339), session.Starred,
		permissionsJSON, agentModelOverridesJSON, customModelsUsedJSON, session.Thinking, parentID)
	return err
}

// addItemTx inserts a session item within a transaction.
func (s *SQLiteSessionStore) addItemTx(ctx context.Context, tx *sql.Tx, sessionID string, position int, item Item) error {
	switch {
	case item.Message != nil:
		msgJSON, err := json.Marshal(item.Message.Message)
		if err != nil {
			return fmt.Errorf("marshaling message: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO session_items (session_id, position, item_type, agent_name, message_json, implicit)
			 VALUES (?, ?, 'message', ?, ?, ?)`,
			sessionID, position, item.Message.AgentName, string(msgJSON), item.Message.Implicit)
		return err

	case item.SubSession != nil:
		// Recursively add the sub-session
		subSession := item.SubSession
		subSession.ParentID = sessionID

		if err := s.addSessionTx(ctx, tx, subSession); err != nil {
			return fmt.Errorf("inserting nested sub-session: %w", err)
		}

		for i, subItem := range subSession.Messages {
			if err := s.addItemTx(ctx, tx, subSession.ID, i, subItem); err != nil {
				return fmt.Errorf("inserting nested sub-session item %d: %w", i, err)
			}
		}

		_, err := tx.ExecContext(ctx,
			`INSERT INTO session_items (session_id, position, item_type, subsession_id)
			 VALUES (?, ?, 'subsession', ?)`,
			sessionID, position, subSession.ID)
		return err

	case item.Summary != "":
		_, err := tx.ExecContext(ctx,
			`INSERT INTO session_items (session_id, position, item_type, summary_text)
			 VALUES (?, ?, 'summary', ?)`,
			sessionID, position, item.Summary)
		return err

	default:
		return nil // Empty item, skip
	}
}

// AddSummary adds a summary item to a session at the next position.
func (s *SQLiteSessionStore) AddSummary(ctx context.Context, sessionID, summary string) error {
	if sessionID == "" {
		return ErrEmptyID
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO session_items (session_id, position, item_type, summary_text)
		 VALUES (?, (SELECT COALESCE(MAX(position), -1) + 1 FROM session_items WHERE session_id = ?), 'summary', ?)`,
		sessionID, sessionID, summary)
	return err
}

// UpdateSessionTokens updates only token/cost fields.
func (s *SQLiteSessionStore) UpdateSessionTokens(ctx context.Context, sessionID string, inputTokens, outputTokens int64, cost float64) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET input_tokens = ?, output_tokens = ?, cost = ? WHERE id = ?",
		inputTokens, outputTokens, cost, sessionID)
	return err
}

// UpdateSessionTitle updates only the title.
func (s *SQLiteSessionStore) UpdateSessionTitle(ctx context.Context, sessionID, title string) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET title = ? WHERE id = ?",
		title, sessionID)
	return err
}

// UpdateSessionFlags updates tools_approved and thinking flags.
func (s *SQLiteSessionStore) UpdateSessionFlags(ctx context.Context, sessionID string, toolsApproved, thinking bool) error {
	if sessionID == "" {
		return ErrEmptyID
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET tools_approved = ?, thinking = ? WHERE id = ?",
		toolsApproved, thinking, sessionID)
	return err
}

// UpsertStreamingAssistantMessage creates or updates a streaming assistant message.
// It finds the last assistant message item for the given session/agent and updates it,
// or creates a new one if none exists.
func (s *SQLiteSessionStore) UpsertStreamingAssistantMessage(ctx context.Context, sessionID, agentName, content, reasoningContent string) error {
	if sessionID == "" {
		return ErrEmptyID
	}

	// Build the message JSON
	msgJSON, err := json.Marshal(chat.Message{
		Role:             chat.MessageRoleAssistant,
		Content:          content,
		ReasoningContent: reasoningContent,
	})
	if err != nil {
		return fmt.Errorf("marshaling streaming message: %w", err)
	}

	// Try to update the last assistant message from this agent
	result, err := s.db.ExecContext(ctx,
		`UPDATE session_items 
		 SET message_json = ?
		 WHERE session_id = ? 
		   AND agent_name = ? 
		   AND item_type = 'message'
		   AND id = (
		       SELECT id FROM session_items 
		       WHERE session_id = ? AND agent_name = ? AND item_type = 'message'
		       ORDER BY position DESC LIMIT 1
		   )`,
		string(msgJSON), sessionID, agentName, sessionID, agentName)
	if err != nil {
		return fmt.Errorf("updating streaming message: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}

	// If no rows were updated, insert a new message
	if rowsAffected == 0 {
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO session_items (session_id, position, item_type, agent_name, message_json, implicit)
			 VALUES (?, (SELECT COALESCE(MAX(position), -1) + 1 FROM session_items WHERE session_id = ?), 'message', ?, ?, 0)`,
			sessionID, sessionID, agentName, string(msgJSON))
		if err != nil {
			return fmt.Errorf("inserting streaming message: %w", err)
		}
	}

	return nil
}
