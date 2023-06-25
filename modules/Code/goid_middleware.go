package goid

import (
	"os"
	"net/http"
	"fmt"
)
/**
 *
 * Check the authorization header on every request
 */
func AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Perform actions before passing the request to the next handler
		fmt.Println("Middleware executed")

		if (os.Getenv("APP_LIVE") == "1"){
			authHeader := r.Header.Get("Authorization")
			if !IsAuthorized(authHeader) {
				fmt.Println("Authorization header was found.")
			} else {
				fmt.Println("No Authorization header...")
			}
		}

		// Call the next handler
		next.ServeHTTP(w, r)

		// Perform actions after the request has been handled by subsequent handlers
		fmt.Println("Middleware finished")
	})
}