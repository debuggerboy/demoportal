package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/session/v2"
    "github.com/go-sql-driver/mysql"
    "github.com/gomodule/redigo/redis"
)

app := fiber.New()
store := redis.NewStore(redis.DialURL("redis://session:6379"))
sessionConfig := session.Config{
    Store: store,
}
app.Use(session.New(sessionConfig))

db, err := sql.Open("mysql", "demouser:demopass@tcp(db:3306)/webportal")
if err != nil {
    panic(err)
}
defer db.Close()

type User struct {
    Username string
    Password string
}

app.Post("/register", func(c *fiber.Ctx) error {
    // Parse the request body
    user := new(User)
    if err := c.BodyParser(user); err != nil {
        return err
    }
    
    // Encrypt the password
    encryptedPassword, err := encryptPassword(user.Password)
    if err != nil {
        return err
    }
    
    // Insert the user into the database
    _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, encryptedPassword)
    if err != nil {
        return err
    }
    
    return c.SendStatus(fiber.StatusCreated)
})


app.Post("/login", func(c *fiber.Ctx) error {
    // Parse the request body
    user := new(User)
    if err := c.BodyParser(user); err != nil {
        return err
    }
    
    // Retrieve the user from the database
    row := db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username)
    var storedPassword string
    if err := row.Scan(&storedPassword); err != nil {
        return err
    }
    
    // Compare the stored password with the input password
    if err := comparePasswords(storedPassword, user.Password); err != nil {
        return fiber.ErrUnauthorized
    }
    
    // Set the session value to indicate successful authentication
    session := session.Get(c)
    session.Set("authenticated", true)
    session.Save()
    
    return c.SendStatus(fiber.StatusOK)
})

func isAuthenticated(c *fiber.Ctx) error {
    session := session.Get(c)
    authenticated, _ := session.GetBool("authenticated")
    if !authenticated {
        return fiber.ErrUnauthorized
    }
    return c.Next()
}

app.Get("/protected", isAuthenticated, func(c *fiber.Ctx) error {
    return c.SendString("Protected route")
})

app.Listen(":3000")

