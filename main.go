package main

import (
	"database/sql"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/fasthttp/session/v2"
	"github.com/fasthttp/session/v2/providers/redis"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Password string
}

func encryptPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func isAuthenticated(c *fiber.Ctx) error {
	session := session.Get(c)
	authenticated, _ := session.GetBool("authenticated")
	if !authenticated {
		return fiber.ErrUnauthorized
	}
	return c.Next()
}

func main() {
	app := fiber.New()

	// Create a Redis session provider
	store, err := redis.New(redis.Config{
		Addr: "session:6379",
	})
	if err != nil {
		panic(err)
	}

	// Set up the session middleware
	sessionConfig := session.Config{
		ProviderConfig: store,
	}
	app.Use(session.New(sessionConfig))

	// Set up the MySQL database connection
	db, err := sql.Open("mysql", "demouser:demopass@tcp(db:3306)/webportal")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	app.Post("/register", func(c *fiber.Ctx) error {
		user := new(User)
		if err := c.BodyParser(user); err != nil {
			return err
		}

		encryptedPassword, err := encryptPassword(user.Password)
		if err != nil {
			return err
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, encryptedPassword)
		if err != nil {
			return err
		}

		return c.SendStatus(fiber.StatusCreated)
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		user := new(User)
		if err := c.BodyParser(user); err != nil {
			return err
		}

		row := db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username)
		var storedPassword string
		if err := row.Scan(&storedPassword); err != nil {
			return err
		}

		if err := comparePasswords(storedPassword, user.Password); err != nil {
			return fiber.ErrUnauthorized
		}

		session := session.Get(c)
		session.Set("authenticated", true)
		if err := session.Save(); err != nil {
			return err
		}

		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/protected", isAuthenticated, func(c *fiber.Ctx) error {
		return c.SendString("Protected route")
	})

	fmt.Println("Server listening on port 3000...")
	app.Listen(":3000")
}
