// package main

// import (
// 	"fmt"

// 	"github.com/gin-contrib/sessions"
// 	"github.com/gin-contrib/sessions/cookie"
// 	"github.com/gin-gonic/gin"
// 	"github.com/m-shinan/week6/controllers"
// 	"github.com/m-shinan/week6/models"
// 	"gorm.io/driver/postgres"
// 	"gorm.io/gorm"
// )

// func main() {
// 	dsn := "host=localhost user=postgres password=mshinan dbname=week6 port=5432 sslmode=disable"

// 	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
// 	if err != nil {
// 		fmt.Println("Connectin to data_base failed")
// 	}

// 	db.AutoMigrate(&models.Users{})

// 	r := gin.Default()

// 	r.Use(controllers.NoCache())
// 	r.LoadHTMLGlob("view/*")

// 	store := cookie.NewStore([]byte("secret"))
// 	r.Use(sessions.Sessions("mysession", store))

// 	controllers.Handler(r, db)

// 	r.Run("localhost:8080")

// }

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/m-shinan/week6/controllers"
	"github.com/m-shinan/week6/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Construct database connection string
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SSLMODE"),
	)

	// Connect to the database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate the Users table
	db.AutoMigrate(&models.Users{})

	// Initialize Gin router
	r := gin.Default()

	// Use NoCache middleware
	r.Use(controllers.NoCache())

	// Load HTML templates
	r.LoadHTMLGlob("view/*")

	// Initialize session store
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	// Initialize controllers
	controllers.Handler(r, db)

	// Start the server
	r.Run("localhost:8080")
}
