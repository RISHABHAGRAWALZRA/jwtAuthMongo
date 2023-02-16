package routes

import (
	"github.com/gin-gonic/gin"
	controller "github.com/rishabhagrawalzra/jwtAuthMongo/controllers"
	"github.com/rishabhagrawalzra/jwtAuthMongo/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
