package middleware

import (
	"errors"
	"os"
	"strings"

	"github.com/VolkHackVH/jwt-auth/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func getSecretKey() []byte {
	return []byte(os.Getenv("SECRET_KEY"))
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "authorization header required"})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "token required"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &auth.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
				return nil, errors.New("unexpected signing method")
			}
			return getSecretKey(), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		claims, ok := token.Claims.(*auth.TokenClaims)
		if !ok || claims.ID == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid user_id in token"})
		}

		c.Set("user_id", claims.ID)
		c.Next()
	}
}
