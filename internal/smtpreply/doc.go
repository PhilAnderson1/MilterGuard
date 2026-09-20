// Package smtpreply builds and submits automatic administration-command
// replies. It owns MIME formatting and one SMTP transaction per call, while
// command authorization, queueing, and worker lifecycle remain with Milter.
package smtpreply
