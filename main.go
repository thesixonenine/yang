package main

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

func initLog() *zerolog.Logger {
	ctx := context.Background()
	// logger
	zerolog.MessageFieldName = "msg"
	zerolog.TimeFieldFormat = "2006-01-02 15:04:05"
	globalLevel, _ := zerolog.ParseLevel("info")
	zerolog.SetGlobalLevel(globalLevel)
	rootLoggerCtx := zerolog.New(os.Stderr).With().Caller().Timestamp().Logger().WithContext(ctx)
	// 路径脱敏
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	return zerolog.Ctx(rootLoggerCtx)
}
func GinLogger(logger *zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		cost := time.Since(start)
		defer logger.Info().
			Int("status", c.Writer.Status()).
			Str("method", c.Request.Method).
			Str("path", path).
			Str("query", query).
			Str("ip", c.ClientIP()).
			Str("user-agent", c.Request.UserAgent()).
			Str("errors", c.Errors.ByType(gin.ErrorTypePrivate).String()).
			Dur("cost", cost).Send()
		c.Next()
	}
}
func GinRecovery(logger *zerolog.Logger, stack bool) gin.HandlerFunc {
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				httpRequest, _ := httputil.DumpRequest(c.Request, false)
				if brokenPipe {
					logger.
						Error().
						Str("path", c.Request.URL.Path).
						Any("error", err).
						Str("request", string(httpRequest)).
						Send()

					// If the connection is dead, we can't write a status to it.
					c.Error(err.(error)) // nolint: errcheck
					c.Abort()
					return
				}

				if stack {
					errors.New(string(debug.Stack()))
					logger.
						Error().
						Stack().
						Err(errors.New(string(debug.Stack()))).
						Str("error", "[Recovery from panic]").
						Str("request", string(httpRequest)).
						Send()

				} else {
					logger.
						Error().
						Str("error", "[Recovery from panic]").
						Any("error", err).
						Str("request", string(httpRequest)).
						Send()
				}
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	}
}

func main() {
	log := initLog()
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(GinLogger(log), GinRecovery(log, true))
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		// 服务连接
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Msgf("listen: %s\n", err)
		}
	}()

	// 等待中断信号以优雅地关闭服务器（设置 5 秒的超时时间）
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Info().Msg("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Msgf("Server Shutdown Err[%s]", err.Error())
	}
	log.Info().Msg("Server exiting")
}
