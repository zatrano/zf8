package middlewares

import (
	"zatrano/configs/sessionconfig"
	"zatrano/services"

	"github.com/gofiber/fiber/v2"
)

func StatusMiddleware(c *fiber.Ctx) error {
	sess, err := sessionconfig.SessionStart(c)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	userID, err := sessionconfig.GetUserIDFromSession(sess)
	if err != nil {
		return c.Redirect("/auth/login")
	}

	authService := services.NewAuthService()
	user, err := authService.GetUserProfile(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Kullanıcı bulunamadı")
	}

	if !user.Status {
		return c.Status(fiber.StatusForbidden).SendString("Kullanıcı aktif değil")
	}

	return c.Next()
}
