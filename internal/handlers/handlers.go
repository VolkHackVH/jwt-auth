package handlers

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/VolkHackVH/jwt-auth/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuthHandler struct {
	service    services.AuthService
	webhookURL string
}

func NewAuthHandler(s services.AuthService, webhookURL string) *AuthHandler {
	return &AuthHandler{service: s, webhookURL: webhookURL}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user, err := h.service.Register(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user_id":  user.ID,
		"username": user.Username,
	})
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	access, refresh, err := h.service.Login(c.Request.Context(),
		req.Username, req.Password, ua, ip)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": ""})
		return
	}
	log.Printf("Received refresh token: %s", req.RefreshToken)

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	userIDstr, exist := c.Get("user_id")
	if !exist {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	userID, err := uuid.Parse(userIDstr.(string))
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid user_id"})
		return
	}

	pgUserID := pgtype.UUID{
		Bytes: userID,
		Valid: true,
	}

	savedUserAgent, savedIP, err := h.service.GetUserAgentAndIP(c.Request.Context(), pgUserID, ua)
	if err != nil {
		c.JSON(401, gin.H{"error": "refresh token not found"})
		return
	}

	if savedUserAgent != ua {
		_ = h.service.Logout(c.Request.Context(), pgUserID, ua)
		c.JSON(401, gin.H{"error": "user agent missmatch"})
		return
	}

	if savedIP != ip && h.webhookURL != "" {
		go func() {
			payload := map[string]string{
				"user_id":   userID.String(),
				"old_ip":    savedIP,
				"new_ip":    ip,
				"userAgent": ua,
				"time":      time.Now().Format("02.01.06 15:04"),
			}

			b, _ := json.Marshal(payload)
			http.Post(h.webhookURL, "application/json", bytes.NewBuffer(b))
		}()
	}

	access, refresh, err := h.service.RefreshToken(c.Request.Context(), req.RefreshToken, ua, ip, pgUserID)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(200, gin.H{"user_id": userID})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	userIDstr, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	userID, err := uuid.Parse(userIDstr.(string))
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
	}

	pgUserID := pgtype.UUID{
		Bytes: userID,
		Valid: true,
	}

	ua := c.GetHeader("User-Agent")

	if err := h.service.Logout(c.Request.Context(), pgUserID, ua); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "logout success"})
}
