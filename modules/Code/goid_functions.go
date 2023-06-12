package goid

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
    "net/http"
    "errors"
)

// Struct representing a user record in the database
type User struct {
    ID    int
	Name string
    Email  string
	Password []byte
    Token string
}

func HomeCheck(w http.ResponseWriter, r *http.Request) {

    fmt.Println("/")
    fmt.Println(r.URL)
    // Send an HTTPS GET request to the server
    // resp, err := client.Get("http://myworldworks.com")
    // if err != nil {
    //     fmt.Println("Oh noes!")
    //     fmt.Println(err)
    //     c.AbortWithError(http.StatusInternalServerError, err)
    //     return
    // }
    // fmt.Println("Client Requested: ", c.Response.URL)
    // fmt.Println("Host: ", c.Response.Host)

    // Get the TLS connection state
    // state, ok := r.TLS
    // if !ok {
    //     http.Error(w, "No TLS connection", http.StatusBadRequest)
    //     return
    // }
   
}

// Function to generate a 21-byte access token and store it in the database
func GenerateAccessToken(db *sql.DB, userID int) (string, error) {
    // Generate a 21-byte random token
    tokenBytes := make([]byte, 21)
    _, err := rand.Read(tokenBytes)
    if err != nil {
        return "", fmt.Errorf("error generating token: %v", err)
    }
    token := base64.URLEncoding.EncodeToString(tokenBytes)

    // Store the token in the user's record in the database
    _, err = db.Exec("UPDATE users SET token = ? WHERE id = ?", token, userID)
    if err != nil {
        return "", fmt.Errorf("error storing token in database: %v", err)
    }

    return token, nil
}



// Function to authenticate a user and generate an access token
func AuthenticateUser(db *sql.DB, email string, password string) (string, error) {

    // Retrieve the user's record from the database
    var user User
    err := db.QueryRow("SELECT id, email, password, token FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.Password, &user.Token)
    if err != nil {
        return "nil", err
    }

    fmt.Println("Comparing hash/pass")

    // Verify the password hash
    err = bcrypt.CompareHashAndPassword(user.Password, []byte(password))
    if err != nil {
        return "nil", err
    }

	fmt.Println("Authentication success! Generating token...")

    // Generate a new access token
    token, err := GenerateAccessToken(db, user.ID)
    if err != nil {
        return "nil", err
    }

    // Update the user's record with the new token
    _, err = db.Exec("UPDATE users SET token = ? WHERE id = ?", token, user.ID)
    if err != nil {
        return "nil", err
    }

	fmt.Println("New Token:\t", token)

    // Set the token in the user struct and return it
    user.Token = token
    return token, nil
}

func VerifyToken(db *sql.DB, email string, token string) (*User, error) {
	// Parse the request body to retrieve the email and token

	// Look up the user in the database based on the email address
	user, err := GetUserByEmail(db, email)
	if err != nil {
		// Handle the error, e.g., return an appropriate response
		return nil, errors.New("Failed to retrieve user...")
	}

	// Verify the token against the user's record
	if user.Token != token {
		return nil, errors.New("Error: Token mismatch...")
	}

	// Token is valid, proceed with further actions
	// ...

	// Send a success response
	fmt.Println("Token verification successful")
    return user, nil
}

// Fetch a user from the DB
func GetUserByEmail(db *sql.DB, email string) (*User, error) {
    var user *User

    err := db.QueryRow("SELECT id, name, email, password, token FROM users WHERE email = ?", email).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Token)
    if err != nil {
        fmt.Println(err)
        return nil, fmt.Errorf("User not found")
    }


	return user, nil

    // return nil, fmt.Errorf("User not found")
	
}