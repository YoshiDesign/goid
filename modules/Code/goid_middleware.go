package goid

import (
	"time"
	"log"
	"github.com/gin-gonic/gin"
	"fmt"
	"net/http"
)

func LogMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        startTime := time.Now()

        // Call the next handler
        c.Next()

        // Log the request details
        log.Printf("[%s] %s - %v\n", c.Request.Method, c.Request.URL.Path, time.Since(startTime))
    }
}

func VerifyCertificateMiddleware() gin.HandlerFunc {
	return func (c *gin.Context) {
		// Retrieve client certificate from request
		tlsConn := c.Request.TLS
		// if !ok {
		// 	c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("could not retrieve TLS connection"))
		// 	return
		// }
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("no client certificate provided"))
			return
		}
		cert := state.PeerCertificates[0]

		// Validate certificate
		err := cert.VerifyHostname("example.com")
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("certificate hostname verification failed: %s", err))
			return
		}
		// ... additional validation logic here ...
		
		// If we've made it this far, the certificate is valid
		c.Next()
	}
}