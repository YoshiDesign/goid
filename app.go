package main 

import (
	"www.github.com/goid/modules/Code"
    "database/sql"
    "crypto/tls"
	"net/http"
    "github.com/go-chi/chi/v5"
    //"github.com/go-chi/chi/v5/middleware"
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
    db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/newtree")
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
    router := chi.NewRouter()
    //router.Use(goid.VerifyCertificateMiddleware())
    //router.Use(goid.LogMiddleware())

	// Define a handler function for a GET request to the root URL
	router.Get("/", goid.HomeCheck)

	router.Get("/check-user", func(w http.ResponseWriter, r *http.Request) {
		var user goid.User
	
		err := db.QueryRow("SELECT id, name, email, password, token FROM users WHERE email = ?", "anthony@mail.com").Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Token)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println("Collected User Record...")
		fmt.Println("ID:", user.ID)
		fmt.Println("Name:", user.Name)
		fmt.Println("Email:", user.Email)
        fmt.Println("Password:", user.Password)
        fmt.Println("Token:", user.Token)

	})

	/**
		Login
	 */
    router.Post("/login", func (w http.ResponseWriter, r *http.Request) {

        // Extract username and password from the request
        email := r.FormValue("email")
        password := r.FormValue("password")
        fmt.Println(email)
        fmt.Println(password)
        // Authenticate the user and perform necessary checks
        // ...
        AuthenticateUser(db, email, password)
        // Return the access token in the response
        response := struct {
            Token string `json:"token"`
        }{
            Token: accessToken,
        }
    
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })


	/**
		Logout
	 */
    router.Get("/logout", func(c *gin.Context) {
        // TODO: Invalidate the access token for the current user
        c.JSON(200, gin.H{})
    })

    // Start the server
    err = router.Run(":8081")
    if err != nil {
        panic(err)
    }
}
