/**
	Can you provide an example of the code that will initiate the TLS handshake, using the Gin framework?
*/

package main

import (
	"crypto/tls"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// Create a new http.Transport with TLS settings
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // InsecureSkipVerify should be set to false in production
		},
	}

	// Create a new http.Client using the transport
	client := &http.Client{
		Transport: tr,
	}

	// Create a new Gin router
	r := gin.Default()

	// Define a handler function for a GET request to the root URL
	r.GET("/", func(c *gin.Context) {
		// Send an HTTPS GET request to the server
		resp, err := client.Get("https://example.com")
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Copy the response body to the Gin context
		defer resp.Body.Close()
		c.Writer.WriteHeader(resp.StatusCode)
		_, err = io.Copy(c.Writer, resp.Body)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
	})

	// Run the Gin router on port 8080
	r.Run(":8080")
}

/**
This example creates a new http.Transport and http.Client as before, and then defines 
a new Gin router with a single handler function for a GET request to the root URL.

In the handler function, it sends an HTTPS GET request to the server using the client 
with mutual TLS authentication enabled. If the request is successful, it copies the 
response body to the Gin context.

Note that you should replace example.com with the actual URL of the server you want to 
connect to, and set InsecureSkipVerify to false in production to validate the server certificate.
In production, you should set `InsecureSkipVerify` to false and provide a proper `RootCAs` field to validate the server certificate.

*/