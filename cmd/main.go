package main

import (
	"context"
	"fmt"
	"os"

	"github.com/VolkHackVH/jwt-auth/internal/db"
	"github.com/VolkHackVH/jwt-auth/internal/router"
	"github.com/jackc/pgx/v5"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

// @title JWT Auth Service
// @version 1.0
// @description Auth service with JWT and refresh tokens
// @host localhost:8080
// @BasePath /
// @schemes http
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	if err := godotenv.Load(); err != nil {
		zap.L().Sugar().Fatalf("error loading environment: %w", err)
	}

	loggerInit(envLocal)

	dbURL := os.Getenv("DATABASE_URL")
	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		zap.L().Sugar().Panicf("error connection database: %w", err)
	}
	defer conn.Close(context.Background())

	zap.L().Info("database connection")

	queries := db.New(conn)

	r := router.InitRouter(queries)

	if err := r.Run(":8080"); err != nil {
		zap.L().Fatal("failed to run server", zap.Error(err))
	}

	zap.L().Info("Server started")

}

func loggerInit(env string) {
	var cfg zap.Config

	switch env {
	case envLocal:
		cfg = zap.NewDevelopmentConfig()
	case envDev, envProd:
		cfg = zap.NewProductionConfig()
	default:
		fmt.Println("used default logger - prod")
		cfg = zap.NewProductionConfig()
	}

	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}

	logger, err := cfg.Build()
	if err != nil {
		fmt.Printf("not init logger: %v", err)
		logger = zap.NewExample()
	}

	zap.ReplaceGlobals(logger)
	logger.Info("Logger initialized", zap.String("env", env))
}
