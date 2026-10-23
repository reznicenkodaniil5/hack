package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"invoicekeeper/internal/apperr"
	"invoicekeeper/internal/auth"
	"invoicekeeper/internal/config"
	"invoicekeeper/internal/models"
	"invoicekeeper/internal/store"
)

type ctxKey string

const userKey ctxKey = "user"

func writeAppError(c *gin.Context, e *apperr.AppError) {
	c.JSON(e.Status, gin.H{"detail": e.Message, "code": e.Code})
}

func authMiddleware(cfg config.Config, st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if h == "" || !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			writeAppError(c, apperr.AuthRequired)
			c.Abort()
			return
		}
		token := strings.TrimSpace(h[7:])
		claims, err := auth.ParseToken(token, cfg.SecretKey)
		if err != nil {
			writeAppError(c, apperr.New(http.StatusUnauthorized, "Invalid or expired token", "AUTH_REQUIRED"))
			c.Abort()
			return
		}
		if claims.JTI != "" && st.IsTokenRevoked(claims.JTI) {
			writeAppError(c, apperr.New(http.StatusUnauthorized, "Token revoked", "AUTH_REQUIRED"))
			c.Abort()
			return
		}
		userID, err := strconv.Atoi(claims.Subject)
		if err != nil {
			writeAppError(c, apperr.AuthRequired)
			c.Abort()
			return
		}
		user, err := st.GetUserByID(userID)
		if err != nil || user == nil || !user.IsActive {
			writeAppError(c, apperr.New(http.StatusUnauthorized, "User not found or inactive", "AUTH_REQUIRED"))
			c.Abort()
			return
		}
		c.Set(string(userKey), user)
		c.Next()
	}
}

func requireAdmin(c *gin.Context) {
	u, ok := currentUser(c)
	if !ok {
		writeAppError(c, apperr.AuthRequired)
		c.Abort()
		return
	}
	if u.Role != "admin" {
		writeAppError(c, apperr.Forbidden)
		c.Abort()
		return
	}
	c.Next()
}

func currentUser(c *gin.Context) (*models.User, bool) {
	v, ok := c.Get(string(userKey))
	if !ok {
		return nil, false
	}
	u, ok := v.(*models.User)
	return u, ok
}

func internalTokenMiddleware(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Internal-Token") != cfg.InternalAPIToken {
			writeAppError(c, apperr.New(http.StatusUnauthorized, "Invalid internal token", "AUTH_REQUIRED"))
			c.Abort()
			return
		}
		c.Next()
	}
}
