package security

// PersistentCenter records into memory ring and optional durable sink.
type PersistentCenter struct {
	*Center
	persist func(Finding) error
	mailer  *AlertMailer
	admin   string
}

// NewPersistentCenter wraps Center with optional persist + mail callbacks.
func NewPersistentCenter(limit int, persist func(Finding) error, mailer *AlertMailer) *PersistentCenter {
	return &PersistentCenter{
		Center:  NewCenter(limit),
		persist: persist,
		mailer:  mailer,
	}
}

// SetAdminURL sets the management link included in alert emails.
func (p *PersistentCenter) SetAdminURL(u string) { p.admin = u }

// Record persists, rings, and maybe emails. Never panics; mail errors ignored for callers.
func (p *PersistentCenter) Record(f Finding) Finding {
	if p == nil || p.Center == nil {
		return f
	}
	f = p.Center.Record(f)
	if p.persist != nil {
		_ = p.persist(f)
	}
	if p.mailer != nil {
		_ = p.mailer.MaybeNotify(f, p.admin)
	}
	return f
}
