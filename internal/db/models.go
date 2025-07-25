// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package db

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type RefreshToken struct {
	ID        pgtype.UUID        `db:"id" json:"id"`
	UserID    pgtype.UUID        `db:"user_id" json:"user_id"`
	TokenHash string             `db:"token_hash" json:"token_hash"`
	UserAgent string             `db:"user_agent" json:"user_agent"`
	IpAddress string             `db:"ip_address" json:"ip_address"`
	CreatedAt pgtype.Timestamptz `db:"created_at" json:"created_at"`
}

type User struct {
	ID           pgtype.UUID        `db:"id" json:"id"`
	Username     string             `db:"username" json:"username"`
	PasswordHash string             `db:"password_hash" json:"password_hash"`
	CreatedAt    pgtype.Timestamptz `db:"created_at" json:"created_at"`
}
