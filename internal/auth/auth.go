package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 24 * time.Hour
)

type AccessToken string
type RefreshToken string

type TokenClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID string, duration time.Duration) (AccessToken, error) {
	claims := TokenClaims{
		ID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	secret := []byte(os.Getenv("SECRET_KEY"))
	tokenStr, err := token.SignedString(secret)
	return AccessToken(tokenStr), err
}

func ParseAccessToken(tokenStr string) (string, error) {
	parsedToken, err := jwt.ParseWithClaims(tokenStr,
		&TokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET_KEY")), nil
		})
	if err != nil || !parsedToken.Valid {
		return "", ErrInvalidToken
	}

	claims, ok := parsedToken.Claims.(*TokenClaims)
	if !ok {
		return "", ErrInvalidToken
	}

	return claims.ID, nil
}

func GenerateRefreshToken() (RefreshToken, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return RefreshToken(base64.StdEncoding.EncodeToString(b)), nil
}

func HashRefreshToken(token RefreshToken) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hashed), err
}

func CompareRefreshToken(hash string, token RefreshToken) error {
	log.Printf("Comparing hash: %s with token: %s", hash, token)
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
}
