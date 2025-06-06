package web

import (
	"sync"
)

// ToolChangeNotifier manages notifications when tools change
type ToolChangeNotifier struct {
	subscribers map[string]chan string // userID -> channel
	mutex       sync.RWMutex
}

// NewToolChangeNotifier creates a new tool change notifier
func NewToolChangeNotifier() *ToolChangeNotifier {
	return &ToolChangeNotifier{
		subscribers: make(map[string]chan string),
	}
}

// Subscribe adds a subscriber for tool changes for a specific user
func (t *ToolChangeNotifier) Subscribe(userID string) <-chan string {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	ch := make(chan string, 10) // Buffered channel
	t.subscribers[userID] = ch
	return ch
}

// Unsubscribe removes a subscriber
func (t *ToolChangeNotifier) Unsubscribe(userID string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if ch, exists := t.subscribers[userID]; exists {
		close(ch)
		delete(t.subscribers, userID)
	}
}

// NotifyToolChange sends a notification that tools have changed for a user
func (t *ToolChangeNotifier) NotifyToolChange(userID string) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if ch, exists := t.subscribers[userID]; exists {
		select {
		case ch <- userID:
			// Notification sent
		default:
			// Channel is full, skip (non-blocking)
		}
	}
}

// Global tool change notifier (can be injected by auth server)
var GlobalToolChangeNotifier *ToolChangeNotifier
