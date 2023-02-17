package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rishabhagrawalzra/jwtAuthMongo/helpers"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("No Authorization token is provided")})
			c.Abort()
			return
		}

		claim, err := helpers.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claim.Email)
		c.Set("first_name", claim.First_name)
		c.Set("last_name", claim.Last_name)
		c.Set("uid", claim.Uid)
		c.Set("user_type", claim.User_type)
		c.Next()
	}
}
