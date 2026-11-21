package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/eswan18/identity/cmd/identity-cli/internal/ops"
	"github.com/eswan18/identity/cmd/identity-cli/internal/ui/views"
	"github.com/go-chi/chi/v5"
)

func (s *Server) resourceRoutes(r chi.Router) {
	r.Get("/resources", s.handleResourceList)
	r.Get("/resources/new", s.handleResourceNewForm)
	r.Post("/resources/new", s.handleResourceCreate)
	r.Get("/resource", s.handleResourceShow)
	r.Post("/resource/review", s.handleResourceReview)
	r.Post("/resource/apply", s.handleResourceApply)
	r.Get("/resource/delete", s.handleResourceDeleteForm)
	r.Post("/resource/delete", s.handleResourceDelete)
}

func (s *Server) handleResourceList(w http.ResponseWriter, r *http.Request) {
	resources, err := ops.ListResources(r.Context(), s.store)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, r, http.StatusOK, views.ResourceList(s.page("Resources"), resources))
}

func resourceFormView(f resourceForm) views.ResourceFormView {
	return views.ResourceFormView{
		URI: f.URI, Name: f.Name, Scopes: views.ScopeRows(f.Scopes, 3),
		DynamicClients: f.DynamicClients, Fingerprint: f.Fingerprint,
	}
}

func (s *Server) handleResourceNewForm(w http.ResponseWriter, r *http.Request) {
	v := resourceFormView(resourceForm{})
	v.New = true
	s.render(w, r, http.StatusOK, views.ResourceForm(s.page("New resource"), v))
}

func (s *Server) handleResourceCreate(w http.ResponseWriter, r *http.Request) {
	f, err := parseResourceForm(r)
	if err == nil {
		var d ops.ResourceDetail
		if d, err = ops.CreateResource(r.Context(), s.store, f.URI, f.Name, f.Scopes, f.DynamicClients); err == nil {
			http.Redirect(w, r, views.ResourceHref("/resource", d.Resource.Uri)+"&saved=1", http.StatusSeeOther)
			return
		}
	}
	v := resourceFormView(f)
	v.New, v.Error = true, err.Error()
	s.render(w, r, http.StatusUnprocessableEntity, views.ResourceForm(s.page("New resource"), v))
}

func (s *Server) loadResource(w http.ResponseWriter, r *http.Request) (ops.ResourceDetail, bool) {
	d, err := ops.GetResource(r.Context(), s.store, r.URL.Query().Get("uri"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, err.Error())
		return ops.ResourceDetail{}, false
	}
	return d, true
}

func (s *Server) renderResourceForm(w http.ResponseWriter, r *http.Request, status int, d ops.ResourceDetail, f resourceForm, errMsg, notice string) {
	v := resourceFormView(f)
	v.URI, v.UsedBy, v.Error, v.Notice = d.Resource.Uri, d.UsedBy, errMsg, notice
	s.render(w, r, status, views.ResourceForm(s.page(d.Resource.Name), v))
}

func (s *Server) handleResourceShow(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadResource(w, r)
	if !ok {
		return
	}
	s.renderResourceForm(w, r, http.StatusOK, d, formFromResource(d), "", noticeFor(r))
}

func (s *Server) handleResourceReview(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.loadResource(w, r)
	if !ok {
		return
	}
	f, err := parseResourceForm(r)
	if err != nil {
		s.renderResourceForm(w, r, http.StatusUnprocessableEntity, cur, f, err.Error(), "")
		return
	}
	notice := ""
	if f.Fingerprint != "" && f.Fingerprint != cur.Fingerprint() {
		notice = "This resource changed since you opened the form. The changes below are against its current state."
	}
	s.renderResourceReview(w, r, http.StatusOK, cur, f, notice)
}

func (s *Server) renderResourceReview(w http.ResponseWriter, r *http.Request, status int, cur ops.ResourceDetail, f resourceForm, notice string) {
	changes := DiffResource(cur, buildResourceUpdate(cur, f))
	if len(changes) == 0 {
		f.Fingerprint = cur.Fingerprint()
		s.renderResourceForm(w, r, http.StatusOK, cur, f, "", strings.TrimSpace(notice+" Nothing to change."))
		return
	}
	hidden := []views.Hidden{{Name: "name", Value: f.Name}}
	for _, row := range views.ScopeRows(f.Scopes, 0) {
		hidden = append(hidden, views.Hidden{Name: "scope_name", Value: row.Name}, views.Hidden{Name: "scope_desc", Value: row.Description})
	}
	if f.DynamicClients {
		hidden = append(hidden, views.Hidden{Name: "dynamic_clients", Value: "on"})
	}
	hidden = append(hidden, views.Hidden{Name: "fingerprint", Value: cur.Fingerprint()})
	uri := cur.Resource.Uri
	s.render(w, r, status, views.Review(s.page("Review changes"), views.ReviewView{
		Kind: "resource", Key: uri, Name: cur.Resource.Name, Changes: changes, Hidden: hidden, Notice: notice,
		ApplyHref: views.ResourceHref("/resource/apply", uri), BackHref: views.ResourceHref("/resource", uri),
	}))
}

func (s *Server) handleResourceApply(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.loadResource(w, r)
	if !ok {
		return
	}
	f, err := parseResourceForm(r)
	if err != nil {
		s.renderResourceForm(w, r, http.StatusUnprocessableEntity, cur, f, err.Error(), "")
		return
	}
	if f.Fingerprint == "" {
		s.fail(w, r, http.StatusBadRequest, "missing review version: start from the resource's page")
		return
	}
	u := buildResourceUpdate(cur, f)
	u.ExpectFingerprint = f.Fingerprint
	uri := cur.Resource.Uri
	if _, err := ops.UpdateResource(r.Context(), s.store, uri, u); err != nil {
		if errors.Is(err, ops.ErrStale) {
			fresh, ok := s.loadResource(w, r)
			if !ok {
				return
			}
			s.renderResourceReview(w, r, http.StatusConflict, fresh, f,
				"This resource changed since you reviewed it. Check the changes again: they are now against its current state.")
			return
		}
		s.renderResourceForm(w, r, http.StatusUnprocessableEntity, cur, f, err.Error(), "")
		return
	}
	http.Redirect(w, r, views.ResourceHref("/resource", uri)+"&saved=1", http.StatusSeeOther)
}

func (s *Server) handleResourceDeleteForm(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadResource(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, views.ResourceDelete(s.page("Delete resource"), d.Resource, ""))
}

func (s *Server) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadResource(w, r)
	if !ok {
		return
	}
	if s.target.IsProd() && strings.TrimSpace(r.PostFormValue("confirm_name")) != d.Resource.Name {
		s.render(w, r, http.StatusUnprocessableEntity,
			views.ResourceDelete(s.page("Delete resource"), d.Resource, "Type the resource's name exactly to delete it from prod."))
		return
	}
	if err := ops.DeleteResource(r.Context(), s.store, d.Resource.Uri); err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, views.ResourceDelete(s.page("Delete resource"), d.Resource, err.Error()))
		return
	}
	http.Redirect(w, r, "/resources", http.StatusSeeOther)
}
