package goid

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "strconv"
    "database/sql"
    "golang.org/x/crypto/bcrypt"
    "net/http"
    "errors"
    "strings"
    "regexp"
)

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

func CreateUser(db *sql.DB, userRequest UserCreateRequest) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)
	if err != nil {
        fmt.Println("Failed to hash password:", err.Error())
		return err
	}

    name := userRequest.Firstname + " " + userRequest.Lastname
    // Prepare the insert statement
	stmt, err := db.Prepare("INSERT INTO users (name, email, password, address_1, address_2, address_3, region_id, region_id_2, phone_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		//w.WriteHeader(http.StatusInternalServerError)
        // TODO Loggin
		fmt.Println("Failed to insert user into the database:", err.Error())
		return err
	}
	defer stmt.Close()

	// Execute the insert statement
	_, err = stmt.Exec(
        name, 
        userRequest.Email, 
        hashedPassword,
        userRequest.AddressOne,
        userRequest.AddressTwo,
        userRequest.RegionOne,
        userRequest.RegionTwo,
        userRequest.ZipCode,
        userRequest.SchoolId,
        userRequest.Phone)

    if err != nil {
		//w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("Failed to insert user into the database:", err.Error())
		return err
	}
    return nil
}

func IsAuthorized(authHeader string) bool {
    // TODO: Implement your authorization logic here
    // You can check if the authHeader is valid and matches your expected format
    // For example, you might check if it contains a valid access token or JWT

    // Placeholder authorization logic
    return strings.HasPrefix(authHeader, "Bearer")
}

func IsValidEmail(email string) bool {
    // Simple email format validation using regex
    // You can implement more comprehensive email validation if needed
    emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
    match, _ := regexp.MatchString(emailRegex, email)
    return match
}

func IsValidRegion(number string) bool {
    // Simple email format validation using regex
    // You can implement more comprehensive email validation if needed
    numberRegex := `^[0-9]{1,5}$`
    match, _ := regexp.MatchString(numberRegex, number)
    return match
}

func IsValidAddress(address string) bool {
    // Simple email format validation using regex
    // You can implement more comprehensive email validation if needed
    addressRegex := `^[a-zA-Z0-9,\'\-\s_.\/#\:]+{0,186}$`
    match, _ := regexp.MatchString(addressRegex, address)
    return match
}

func IsValidPassword(password string) bool {
    // Simple email format validation using regex
    // You can implement more comprehensive email validation if needed
    passwordRegex := `^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#.$%^&*])[a-zA-Z\d!@#.$%^&*]{8,50}$`
    match, _ := regexp.MatchString(passwordRegex, password)
    return match
}

func IsValidPhoneNumber(phoneNumber string) bool {
	// Regular expression pattern for a valid phone number
	// Adjust the pattern according to your specific phone number format requirements
	pattern := `^\+[1-9]\d{1,3}[ ]?\(?\d{1,4}\)?[ ]?\d{1,16}$`

	// Create a regular expression object
	regex := regexp.MustCompile(pattern)

	// Check if the phone number matches the pattern
	return regex.MatchString(phoneNumber)
}

func IsValidUserCreateRequest(request UserCreateRequest) (bool, error) {
    fmt.Println("IsValidUserCreateRequest - Validation Function...")
    // Validate email format
    if !IsValidEmail(request.Email) {
        return false, errors.New("Invalid Stuff")
    }
    fmt.Println("1 - Validation Function...")
    if !IsValidRegion(strconv.Itoa(request.RegionOne)) {
        return false, errors.New("Invalid Country Selection")
    }
    fmt.Println("2 - Validation Function...")
    if !IsValidRegion(strconv.Itoa(request.RegionTwo)) {
        return false, errors.New("Invalid Region Selection")
    }
    fmt.Println("3 - Validation Function...")
    if !IsValidAddress(request.AddressOne + " " + request.AddressTwo) {
        return false, errors.New("Invalid Region Selection")
    }
    fmt.Println("4 - Validation Function...")
    // Validate phone number format
    if !IsValidPhoneNumber(request.Phone) {
        return false, errors.New("Invalid Phone Number")
    }
    fmt.Println("5 - Validation Function...")
    if !IsValidPassword(request.Password) {
        return false, errors.New("Invalid Password")
    }
    fmt.Println("6 - Validation Function...")
    // Check if password and confirm_password match
    if request.Password != request.PasswordConfirmation {
        return false, errors.New("Invalid Password Confirmation")
    }
    fmt.Println("COMPLETE - Validation Function...")
    return true, nil
}