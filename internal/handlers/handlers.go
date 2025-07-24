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

type GenerateTokensRequest struct {
	UserAgent string `json:"user_agent"`
}

// GenerateTokens godoc
// @Summary Генерация токенов по GUID
// @Description Генерирует access и refresh токены для заданного GUID (user_id)
// @Tags auth
// @Accept json
// @Produce json
// @Param guid path string true "User GUID"
// @Param request body handlers.GenerateTokensRequest true "User-Agent клиента"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /tokens/{guid} [post]
func (h *AuthHandler) GenerateTokens(c *gin.Context) {
	guid := c.Param("guid")

	var req GenerateTokensRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userID, err := uuid.Parse(guid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid GUID format"})
		return
	}

	pgUserID := pgtype.UUID{
		Bytes: userID,
		Valid: true,
	}

	ip := c.ClientIP()
	access, refresh, err := h.service.GenerateTokens(c.Request.Context(), pgUserID, req.UserAgent, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Register godoc
// @Summary Регистрация пользователя
// @Description Регистрирует нового пользователя с логином и паролем
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handlers.RegisterRequest true "Данные для регистрации"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /register [post]
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

// Login godoc
// @Summary Вход пользователя
// @Description Авторизует пользователя и возвращает пару токенов
// @Tags auth
// @Accept json
// @Produce json
// @Param login body handlers.LoginRequest true "Данные для входа"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
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

// Refresh godoc
// @Summary Обновить токены
// @Description Обновляет access и refresh токены
// @Tags auth
// @Accept json
// @Produce json
// @Param refreshToken body handlers.RefreshRequest true "Refresh токен"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /refresh [post]
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

// Me godoc
// @Summary Получение текущего пользователя
// @Description Возвращает user_id авторзованного пользователя
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(200, gin.H{"user_id": userID})
}

// Logout godoc
// @Summary Выход/Деавторизация
// @Description Удаляет refresh токен пользователя по user_id и User-Agent
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /logout [post]
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
