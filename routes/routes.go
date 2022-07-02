package routes

import (
	"github.com/gofiber/fiber/v2"
	"go-auth/controllers"
)

func Setup(app *fiber.App) {
	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Get("/api/user", controllers.User)
	app.Get("/api/users", controllers.Users)
	app.Put("/api/update", controllers.Update)
	app.Post("/api/logout", controllers.Logout)
	app.Delete("/api/delete", controllers.Delete)
}
