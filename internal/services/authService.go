package services

import (
	"context"
	"fmt"

	"github.com/VolkHackVH/jwt-auth/internal/auth"
	"github.com/VolkHackVH/jwt-auth/internal/db"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(ctx context.Context,
		username,
		password string,
	) (db.User, error)

	Login(ctx context.Context,
		username,
		password,
		userAgent,
		ip string,
	) (auth.AccessToken, auth.RefreshToken, error)

	RefreshToken(ctx context.Context,
		oldRefreshToken string,
		userAgent,
		ip string,
		userID pgtype.UUID,
	) (auth.AccessToken, auth.RefreshToken, error)

	Logout(ctx context.Context, userID pgtype.UUID, userAgent string) error
	GetUserAgentAndIP(ctx context.Context,
		userID pgtype.UUID,
		userAgent string,
	) (string, string, error)

	GenerateTokens(ctx context.Context,
		userID pgtype.UUID,
		userAgent,
		ip string,
	) (auth.AccessToken, auth.RefreshToken, error)
}

type UserService struct {
	db *db.Queries
}

func NewUserService(query *db.Queries) *UserService {
	return &UserService{
		db: query,
	}
}

func (s *UserService) Register(ctx context.Context,
	username, password string,
) (db.User, error) {
	hashPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return db.User{}, fmt.Errorf("error hashing password: %w", err)
	}

	user, err := s.db.CreateUser(ctx, db.CreateUserParams{
		Username:     username,
		PasswordHash: string(hashPass),
	})
	if err != nil {
		return db.User{}, fmt.Errorf("error register user: %w", err)
	}

	return db.User{
		ID:        user.ID,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (s *UserService) Login(ctx context.Context,
	username, password, userAgent, ip string,
) (auth.AccessToken, auth.RefreshToken, error) {
	user, err := s.db.LoginUser(ctx, username)
	if err != nil {
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", fmt.Errorf("invalid credentials: %w", err)
	}

	accessToken, err := auth.GenerateAccessToken(user.ID.String(), auth.AccessTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	hashedToken, err := auth.HashRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash refresh token: %w", err)
	}

	tokenRecord, err := s.db.FindRefreshToken(ctx, db.FindRefreshTokenParams{
		UserID:    user.ID,
		UserAgent: userAgent,
	})

	if err == nil {
		_, err = s.db.UpdateToken(ctx, db.UpdateTokenParams{
			ID:        tokenRecord.ID,
			TokenHash: hashedToken,
		})
	} else {
		_, err = s.db.CreateToken(ctx, db.CreateTokenParams{
			UserID:    user.ID,
			TokenHash: hashedToken,
			UserAgent: userAgent,
			IpAddress: ip,
		})
	}

	if err != nil {
		return "", "", fmt.Errorf("failed to save refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *UserService) RefreshToken(ctx context.Context,
	oldRefreshToken, userAgent, ip string, userID pgtype.UUID,
) (auth.AccessToken, auth.RefreshToken, error) {
	rt, err := s.db.FindRefreshToken(ctx, db.FindRefreshTokenParams{
		UserID:    userID,
		UserAgent: userAgent,
	})
	if err != nil {
		return "", "", fmt.Errorf("refresh token not found: %w", err)
	}

	if err = auth.CompareRefreshToken(rt.TokenHash, auth.RefreshToken(oldRefreshToken)); err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	newAccessToken, err := auth.GenerateAccessToken(userID.String(), auth.AccessTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("error generate access token: %w", err)
	}

	newRefreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	hashedNewToken, err := auth.HashRefreshToken(newRefreshToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to hashing new refresh token: %w", err)
	}

	_, err = s.db.UpdateToken(ctx, db.UpdateTokenParams{
		ID:        rt.ID,
		TokenHash: hashedNewToken,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed update refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}

func (s *UserService) Logout(ctx context.Context,
	userID pgtype.UUID, userAgent string,
) error {
	if err := s.db.DeleteToken(ctx, db.DeleteTokenParams{
		UserID:    userID,
		UserAgent: userAgent,
	}); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	return nil
}

func (s *UserService) GenerateTokens(ctx context.Context,
	userID pgtype.UUID,
	userAgent,
	ip string,
) (auth.AccessToken, auth.RefreshToken, error) {

	_, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("user not found")
	}

	accessToken, err := auth.GenerateAccessToken(userID.String(), auth.AccessTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token")
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token")
	}

	hashedToken, err := auth.HashRefreshToken(refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash refresh token")
	}

	_, err = s.db.CreateToken(ctx, db.CreateTokenParams{
		UserID:    userID,
		TokenHash: hashedToken,
		UserAgent: userAgent,
		IpAddress: ip,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to save refresh token")
	}

	return accessToken, refreshToken, nil
}

func (s *UserService) GetUserAgentAndIP(ctx context.Context,
	userID pgtype.UUID, userAgent string,
) (string, string, error) {
	tokenRecord, err := s.db.FindRefreshToken(ctx, db.FindRefreshTokenParams{
		UserID:    userID,
		UserAgent: userAgent,
	})
	if err != nil {
		return "", "", err
	}

	return tokenRecord.UserAgent, tokenRecord.IpAddress, nil
}
