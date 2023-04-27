package main 

import (
	"www.github.com/goid/modules/Code"
    "database/sql"
    "crypto/tls"
	"net/http"
    "github.com/gin-gonic/gin"
	"fmt"
    "io"
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

    // Connect to the database - Currently uses a remote DB host (Local VM - Homestead)
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

    // Create a new http.Transport with TLS settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // InsecureSkipVerify should be set to false in production
		},
	}

	// Create a new http.Client using the transport
	client := &http.Client{
		Transport: tr,
	}

    // Initialize the Gin router
    router := gin.Default()

	// Define a handler function for a GET request to the root URL
	router.GET("/", func(c *gin.Context) {
		// Send an HTTPS GET request to the server
		resp, err := client.Get("http://myworldworks.com")
		if err != nil {
            fmt.Println("Oh noes!")
            fmt.Println(err)
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
        fmt.Println("Client Requested: ", c.Response.URL)
        fmt.Println("Host: ", c.Response.Host)

        // Get the TLS connection state
        // state, ok := r.TLS
        // if !ok {
        //     http.Error(w, "No TLS connection", http.StatusBadRequest)
        //     return
        // }

        fmt.Println("Get Anthony Lyristis.com")

        body, err := io.ReadAll(resp.Body)
        if err != nil {
            // log.Fatal(err)
        }

        fmt.Printf("Code: %d\n", resp.StatusCode)
        fmt.Printf("Body: %s\n", body)

		// Copy the response body to the Gin context
		defer resp.Body.Close()

		c.Writer.WriteHeader(resp.StatusCode)
		_, err = io.Copy(c.Writer, resp.Body)
		if err != nil {
            fmt.Println("Oh noes again!")
            fmt.Println(err)
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
        fmt.Println(resp.Body)
        fmt.Println(body)
        //return c.IndentedJSON(http.StatusOK, body)
	})

	router.GET("/check-user", func(c *gin.Context) {
		var user goid.User
	
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
