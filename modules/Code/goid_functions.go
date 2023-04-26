package goid

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
)

// Struct representing a user record in the database
type User struct {
    ID    int
	Name string
    Email  string
	Password []byte
    Token string
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

	fmt.Println("Token has been updated.", token)

    // Set the token in the user struct and return it
    user.Token = token
    return token, nil
}
