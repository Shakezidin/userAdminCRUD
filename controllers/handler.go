package controllers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Handler(c *gin.Engine, db *gorm.DB) {
	h := UserControls{DB: db}
	c.GET("/MyWorld", h.ShowSingUpPage)
	c.POST("/signup", h.Validate)
	c.GET("/login", h.Login)
	c.POST("/login", h.Loginvalidation)
	c.GET("/Home", h.Homepage)
	c.GET("/userlogout", h.LogginOut)

	c.GET("/adminloginpage", h.Adminloginpage)
	c.POST("/adminloginpage", h.AdminValidation)
	c.GET("/adminpanel", h.Adminpanel)
	c.POST("/adminpanel", h.Delete)
	c.GET("/search", h.Search)
	c.GET("/logoutadmin", h.Logoutadmin)
	c.POST("/adminedit", h.Adminedit)
	c.POST("/useredited", h.Admineditsave)
	c.POST("/admincreate", h.Admincreate)
	c.POST("/admincreated", h.Admincreated)
}
