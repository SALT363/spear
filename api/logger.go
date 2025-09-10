package api

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger interface
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	With(args ...interface{}) Logger
}

// simpleLogger implements Logger
type simpleLogger struct {
	prefix string
	fields map[string]interface{}
	mu     *sync.Mutex
}

// NewLogger creates a new logger with optional prefix
func NewLogger(prefix string) Logger {
	return &simpleLogger{
		prefix: prefix,
		fields: map[string]interface{}{},
		mu:     &sync.Mutex{},
	}
}

func (l *simpleLogger) Debug(msg string, args ...interface{}) {
	l.log("DBUG", msg, args...)
}

func (l *simpleLogger) Info(msg string, args ...interface{}) {
	l.log("INFO", msg, args...)
}

func (l *simpleLogger) Warn(msg string, args ...interface{}) {
	l.log("WARN", msg, args...)
}

func (l *simpleLogger) Error(msg string, args ...interface{}) {
	l.log("CRIT", msg, args...)
}

func (l *simpleLogger) With(args ...interface{}) Logger {
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	// parse args into key=value
	for i := 0; i < len(args)-1; i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		newFields[key] = args[i+1]
	}
	return &simpleLogger{
		prefix: l.prefix,
		fields: newFields,
		mu:     l.mu,
	}
}

// log prints formatted log line
func (l *simpleLogger) log(level, msg string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2000-01-01 23:59:59")
	prefixPart := ""
	if l.prefix != "" {
		prefixPart = fmt.Sprintf("[%s] ", l.prefix)
	}

	// combine fields + args
	allFields := make(map[string]interface{})
	for k, v := range l.fields {
		allFields[k] = v
	}
	for i := 0; i < len(args)-1; i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		allFields[key] = args[i+1]
	}

	// format key=value part
	fieldsStr := ""
	if len(allFields) > 0 {
		for k, v := range allFields {
			fieldsStr += fmt.Sprintf("%s=%v ", k, v)
		}
		fieldsStr = fmt.Sprintf(" (%s)", fieldsStr)
	}

	fmt.Fprintf(os.Stdout, "%s [%s] %s%s%s\n", timestamp, level, prefixPart, msg, fieldsStr)
}
