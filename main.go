package main

import (
	"fmt"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/shaikhzidhin/controllers"
	"github.com/shaikhzidhin/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := "host=localhost user=postgres password=Sinu1090. dbname=person port=5432 sslmode=disable"

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Connectin to data_base failed")
	}

	db.AutoMigrate(&models.Users{})

	r := gin.Default()

	r.Use(controllers.NoCache())
	r.LoadHTMLGlob("html pages/*")

	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	controllers.Handler(r, db)

	r.Run("localhost:8080")

}




