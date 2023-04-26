package main 

import (
	"www.github.com/goid/modules/Code"
    "database/sql"
    "github.com/gin-gonic/gin"
	"fmt"	
	_ "github.com/go-sql-driver/mysql"
	// "os"
)

// Main function to start the server
func main() {

	// cfg := map[string] string {
	// 	User:   os.Getenv("DBUSER"),
	// 	Passwd: os.Getenv("DBPASS"),
	// 	Addr: os.Getenv("DBHOST"),
	// 	SSHPort: os.Getenv("DBPORT"),
	// 	DBName: os.Getenv("DBNAME"),
    // }

    // Connect to the database
    db, err := sql.Open("mysql", "homestead:secret@tcp(192.168.10.10:3306)/newtree")
    if err != nil {
        panic(err)
    }
	// pingErr := db.Ping()
    // if pingErr != nil {
    //     fmt.Println(pingErr)
    // }
    // fmt.Println("Connected!")
    defer db.Close()

    // Initialize the Gin router
    router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		var user goid.User
		fmt.Println("Hello, Gin!")

		err := db.QueryRow("SELECT id, name, email, password, token FROM users WHERE email = ?", "anthony@mail.com").Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Token)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println("Collected User Record...")
		fmt.Println("ID:", user.ID)
		fmt.Println("Name:", user.Name)
		fmt.Println("Email:", user.Email)

	})

	/**
		Login
	 */
    router.POST("/login", func(c *gin.Context) {
        // Extract the username and password from the request body
        var reqBody struct {
            Username string `form:"email" json:"username"`
            Password string `form:"password" json:"password"`
        }
        if err := c.ShouldBindJSON(&reqBody); err != nil {
            c.JSON(400, gin.H{"error": "Invalid request body"})
            return
        }

		fmt.Println(reqBody.Username)
		fmt.Println(reqBody.Password)

        // Authenticate the user
        token, err := goid.AuthenticateUser(db, reqBody.Username, reqBody.Password)
        if err != nil {
			fmt.Println(err)
            c.JSON(401, gin.H{"error": "Invalid username or password"})
            return
        }

        // Return the access token to the client
        c.JSON(200, gin.H{"token": token})
    })


	/**
		Logout
	 */
    router.GET("/logout", func(c *gin.Context) {
        // TODO: Invalidate the access token for the current user
        c.JSON(200, gin.H{})
    })

    // Start the server
    err = router.Run(":8080")
    if err != nil {
        panic(err)
    }
}
