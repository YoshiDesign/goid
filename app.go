package main 

import (
	"www.github.com/goid/modules/Code"
    "database/sql"
    //"crypto/tls"
	"net/http"
    "encoding/json"
    "golang.org/x/crypto/bcrypt"
    "github.com/go-chi/chi/v5"
    "time"
    //"github.com/go-chi/chi/v5/middleware"
	"fmt"
    //"io"
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
    db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/goid")
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
	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{
	// 		InsecureSkipVerify: false, // InsecureSkipVerify should be set to false in production
	// 	},
	// }

	// Create a new http.Client using the transport
	// client := &http.Client{
	// 	Transport: tr,
	// }

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
        Requires JSON body, no query params
	 */
    router.Post("/login", func (w http.ResponseWriter, r *http.Request) {
        
        var login goid.LoginRequest
        err := json.NewDecoder(r.Body).Decode(&login)
        fmt.Println(login.Email)
        fmt.Println(login.Password)

        // Authenticate the user and perform necessary checks
        token, err := goid.AuthenticateUser(db, login.Email, login.Password)
        if err != nil {
            fmt.Println("Error:", err)
            return
        } 

        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

        // Return the access token in the response
        response := struct {
            Token string `json:"token"`
        }{
            Token: token,
        }

        cookie := http.Cookie{
			Name:     "goid_token",
			Value:    "example value",
			HttpOnly: true,
            Domain: "localhost",
            Secure: false,
            Path: "/",
            MaxAge: 0,
            Expires: time.Now().Add(10000),
            SameSite: http.SameSiteLaxMode,
		}
        
        http.SetCookie(w, &cookie)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })

    router.Post("/getCookies", func(w http.ResponseWriter, r *http.Request) {
        cookie := http.Cookie{
			Name:     "goid_token",
			Value:    "example value",
			HttpOnly: true,
            Domain: "127.0.0.1",
            Secure: false,
            Path: "/",
            MaxAge: 0,
            Expires: time.Now().Add(10000),
            SameSite: http.SameSiteLaxMode,
		}
        
        http.SetCookie(w, &cookie)
    })

    router.Post("/verifyToken", func(w http.ResponseWriter, r *http.Request) {
        var verify goid.VerifyRequest
        err := json.NewDecoder(r.Body).Decode(&verify)
        user, err := goid.VerifyToken(db, verify.Email, verify.Token)
        if err != nil {
            http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")

        response := struct {
            User_id int `json:"user_id"`
            Token string `json:"token"`
        }{
            User_id: user.ID,
            Token: user.Token,
        }

        json.NewEncoder(w).Encode(response)
    })

    router.Post("/bcrypt", func (w http.ResponseWriter, r *http.Request) {

        // Extract username and password from the request
        message := r.FormValue("pass")
        hashedBytes, err := bcrypt.GenerateFromPassword([]byte(message), bcrypt.DefaultCost)
        if err != nil {
            fmt.Println("Error:",err)
        }
        w.Write([]byte(fmt.Sprintf("hashed:%s", hashedBytes)))
    })

    router.Post("/securekey", func (w http.ResponseWriter, r *http.Request) {
        key, err := goid.GenerateSecureKey(128)
        if err != nil {
            //
        }
        w.Write([]byte(fmt.Sprintf("key:%s", key)))
    })

	/**
		Logout
	 */
    router.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
        // TODO: Invalidate the access token for the current user
        //c.JSON(200, gin.H{})
    })

    // Start the server
    http.ListenAndServe(":8081", router)
    //http.ListenAndServeTLS(":8081", "/home/yoshi/.ssh/newcert.pem", "/home/yoshi/.ssh/newkey.pem", router)

}
