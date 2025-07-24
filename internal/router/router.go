package router

import (
	"os"

	"github.com/VolkHackVH/jwt-auth/internal/db"
	"github.com/VolkHackVH/jwt-auth/internal/handlers"
	"github.com/VolkHackVH/jwt-auth/internal/middleware"
	"github.com/VolkHackVH/jwt-auth/internal/services"
	"github.com/gin-gonic/gin"
)

func InitRouter(db *db.Queries) *gin.Engine {
	r := gin.Default()

	r.Use(
		gin.Logger(),
	)

	r.SetTrustedProxies([]string{"127.0.0.1"})
	service := services.NewUserService(db)
	handler := handlers.NewAuthHandler(service, os.Getenv("WEBHOOK_URL"))
	registerAPIRoutes(r, handler)

	return r
}

func registerAPIRoutes(r *gin.Engine, h *handlers.AuthHandler) {

	r.POST("/login", h.Login)
	r.POST("/register", h.Register)

	r.POST("/refresh", middleware.JWTMiddleware(), h.Refresh)

	auth := r.Group("/")
	auth.Use(middleware.JWTMiddleware())
	{
		auth.GET("/me", h.Me)
		auth.POST("/logout", h.Logout)
	}
}
