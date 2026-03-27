package handlers

import (
	"github.com/osama1998h/uniauth/internal/domain"
)

// Response view models — keep the API stable and hide internal fields.

func userResponse(u *domain.User) map[string]any {
	return map[string]any{
		"id":               u.ID,
		"org_id":           u.OrgID,
		"email":            u.Email,
		"full_name":        u.FullName,
		"is_active":        u.IsActive,
		"is_superuser":     u.IsSuperuser,
		"email_verified_at": u.EmailVerifiedAt,
		"last_login_at":    u.LastLoginAt,
		"created_at":       u.CreatedAt,
		"updated_at":       u.UpdatedAt,
	}
}

func orgResponse(o *domain.Organization) map[string]any {
	return map[string]any{
		"id":         o.ID,
		"name":       o.Name,
		"slug":       o.Slug,
		"is_active":  o.IsActive,
		"created_at": o.CreatedAt,
		"updated_at": o.UpdatedAt,
	}
}

func roleResponse(r *domain.Role) map[string]any {
	return map[string]any{
		"id":          r.ID,
		"org_id":      r.OrgID,
		"name":        r.Name,
		"description": r.Description,
		"created_at":  r.CreatedAt,
	}
}

func permissionResponse(p *domain.Permission) map[string]any {
	return map[string]any{
		"id":          p.ID,
		"name":        p.Name,
		"description": p.Description,
	}
}

func apiKeyResponse(k *domain.APIKey) map[string]any {
	return map[string]any{
		"id":          k.ID,
		"org_id":      k.OrgID,
		"name":        k.Name,
		"key_prefix":  k.KeyPrefix,
		"scopes":      k.Scopes,
		"expires_at":  k.ExpiresAt,
		"last_used_at": k.LastUsedAt,
		"created_at":  k.CreatedAt,
	}
}
