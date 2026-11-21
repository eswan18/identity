package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui/views"
	"github.com/go-chi/chi/v5"
)

func (s *Server) clientRoutes(r chi.Router) {
	r.Get("/clients", s.handleClientList)
	r.Get("/clients/new", s.handleClientNewForm)
	r.Post("/clients/new", s.handleClientCreate)
	r.Get("/client", s.handleClientShow)
	r.Post("/client/review", s.handleClientReview)
	r.Post("/client/apply", s.handleClientApply)
	r.Get("/client/delete", s.handleClientDeleteForm)
	r.Post("/client/delete", s.handleClientDelete)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = c.Render(r.Context(), w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, views.Message(s.page("Error"), msg))
}

func (s *Server) handleClientList(w http.ResponseWriter, r *http.Request) {
	clients, err := ops.ListClients(r.Context(), s.store)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, r, http.StatusOK, views.ClientList(s.page("Clients"), clients))
}

// formView is the edit (or create) form showing f.
func (s *Server) formView(r *http.Request, f clientForm) (views.ClientFormView, error) {
	all, err := ops.ListResources(r.Context(), s.store)
	if err != nil {
		return views.ClientFormView{}, err
	}
	return views.ClientFormView{
		Name: f.Name, RedirectURIs: f.RedirectURIs, Scopes: f.Scopes, Resources: f.Resources,
		DefaultResource: f.DefaultResource, Trusted: f.Trusted, Fingerprint: f.Fingerprint,
		AllResources: all,
	}, nil
}

func (s *Server) handleClientNewForm(w http.ResponseWriter, r *http.Request) {
	v, err := s.formView(r, clientForm{Scopes: []string{"openid"}})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	v.New = true
	s.render(w, r, http.StatusOK, views.ClientForm(s.page("New client"), v))
}

func (s *Server) handleClientCreate(w http.ResponseWriter, r *http.Request) {
	f := parseClientForm(r)
	confidential := r.PostFormValue("confidential") == "on"
	detail, secret, err := ops.CreateClient(r.Context(), s.store, ops.ClientCreate{
		Name: f.Name, RedirectURIs: f.RedirectURIs, Scopes: f.Scopes, Resources: f.Resources,
		Confidential: confidential, Trusted: f.Trusted, DefaultResource: f.DefaultResource,
	})
	if err != nil {
		v, verr := s.formView(r, f)
		if verr != nil {
			s.fail(w, r, http.StatusInternalServerError, verr.Error())
			return
		}
		v.New, v.Error = true, err.Error()
		s.render(w, r, http.StatusUnprocessableEntity, views.ClientForm(s.page("New client"), v))
		return
	}
	s.render(w, r, http.StatusOK, views.ClientCreated(s.page("Client created"), detail.Client, secret))
}

// loadClient reads the client named by ?id=, rendering a 404 if there is none.
func (s *Server) loadClient(w http.ResponseWriter, r *http.Request) (ops.ClientDetail, bool) {
	d, err := ops.GetClient(r.Context(), s.store, r.URL.Query().Get("id"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, err.Error())
		return ops.ClientDetail{}, false
	}
	return d, true
}

// loadEditableClient is loadClient for the edit paths: only clients
// registered here are edited (a metadata-document client's details come from
// its document).
func (s *Server) loadEditableClient(w http.ResponseWriter, r *http.Request) (ops.ClientDetail, bool) {
	d, ok := s.loadClient(w, r)
	if ok && d.Client.Kind != "registered" {
		s.fail(w, r, http.StatusBadRequest, "a "+d.Client.Kind+" client can't be edited here")
		return ops.ClientDetail{}, false
	}
	return d, ok
}

func (s *Server) handleClientShow(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadClient(w, r)
	if !ok {
		return
	}
	if d.Client.Kind != "registered" {
		s.render(w, r, http.StatusOK, views.ClientReadOnly(s.page(d.Client.Name), d.Client))
		return
	}
	s.renderEditForm(w, r, http.StatusOK, d, formFromClient(d), "", noticeFor(r))
}

func noticeFor(r *http.Request) string {
	if r.URL.Query().Get("saved") == "1" {
		return "Saved."
	}
	return ""
}

func (s *Server) renderEditForm(w http.ResponseWriter, r *http.Request, status int, d ops.ClientDetail, f clientForm, errMsg, notice string) {
	v, err := s.formView(r, f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	v.ClientID, v.Confidential, v.Error, v.Notice = d.Client.ClientID, d.Client.IsConfidential, errMsg, notice
	s.render(w, r, status, views.ClientForm(s.page(d.Client.Name), v))
}

func (s *Server) handleClientReview(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.loadEditableClient(w, r)
	if !ok {
		return
	}
	f := parseClientForm(r)
	notice := ""
	if f.Fingerprint != "" && f.Fingerprint != cur.Fingerprint() {
		notice = "This client changed since you opened the form. The changes below are against its current state."
	}
	s.renderClientReview(w, r, http.StatusOK, cur, f, notice)
}

// renderClientReview shows what f would change on cur, with f (and the
// version it is diffed against) carried in hidden fields for apply.
func (s *Server) renderClientReview(w http.ResponseWriter, r *http.Request, status int, cur ops.ClientDetail, f clientForm, notice string) {
	changes := DiffClient(cur, buildClientUpdate(cur, f))
	if len(changes) == 0 {
		f.Fingerprint = cur.Fingerprint()
		s.renderEditForm(w, r, http.StatusOK, cur, f, "", strings.TrimSpace(notice+" Nothing to change."))
		return
	}
	hidden := []views.Hidden{
		{Name: "name", Value: f.Name},
		{Name: "redirect_uris", Value: strings.Join(f.RedirectURIs, "\n")},
		{Name: "scopes", Value: strings.Join(f.Scopes, " ")},
		{Name: "default_resource", Value: f.DefaultResource},
		{Name: "fingerprint", Value: cur.Fingerprint()},
	}
	for _, uri := range f.Resources {
		hidden = append(hidden, views.Hidden{Name: "resources", Value: uri})
	}
	if f.Trusted {
		hidden = append(hidden, views.Hidden{Name: "trusted", Value: "on"})
	}
	id := cur.Client.ClientID
	s.render(w, r, status, views.Review(s.page("Review changes"), views.ReviewView{
		Kind: "client", Key: id, Name: cur.Client.Name, Changes: changes, Hidden: hidden, Notice: notice,
		ApplyHref: views.ClientHref("/client/apply", id), BackHref: views.ClientHref("/client", id),
	}))
}

func (s *Server) handleClientApply(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.loadEditableClient(w, r)
	if !ok {
		return
	}
	f := parseClientForm(r)
	u := buildClientUpdate(cur, f)
	// The version the operator reviewed. If the client no longer matches it,
	// UpdateClient writes nothing and returns ErrStale.
	u.ExpectFingerprint = f.Fingerprint
	if u.ExpectFingerprint == "" {
		s.fail(w, r, http.StatusBadRequest, "missing review version: start from the client's page")
		return
	}
	id := cur.Client.ClientID
	if _, err := ops.UpdateClient(r.Context(), s.store, id, u); err != nil {
		if errors.Is(err, ops.ErrStale) {
			fresh, ok := s.loadEditableClient(w, r)
			if !ok {
				return
			}
			s.renderClientReview(w, r, http.StatusConflict, fresh, f,
				"This client changed since you reviewed it. Check the changes again: they are now against its current state.")
			return
		}
		s.renderEditForm(w, r, http.StatusUnprocessableEntity, cur, f, err.Error(), "")
		return
	}
	http.Redirect(w, r, views.ClientHref("/client", id)+"&saved=1", http.StatusSeeOther)
}

func (s *Server) handleClientDeleteForm(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadClient(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, views.ClientDelete(s.page("Delete client"), d.Client, ""))
}

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadClient(w, r)
	if !ok {
		return
	}
	if s.target.IsProd() && strings.TrimSpace(r.PostFormValue("confirm_name")) != d.Client.Name {
		s.render(w, r, http.StatusUnprocessableEntity,
			views.ClientDelete(s.page("Delete client"), d.Client, "Type the client's name exactly to delete it from prod."))
		return
	}
	if err := ops.DeleteClient(r.Context(), s.store, d.Client.ClientID); err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, views.ClientDelete(s.page("Delete client"), d.Client, err.Error()))
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}
