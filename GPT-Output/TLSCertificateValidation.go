/**
	Using the crypto/tls package in Go, how can I retrieve the client's Certificate and validate  its authenticity? 
*/

func myHandler(w http.ResponseWriter, r *http.Request) {
    // Get the TLS connection state
    state, ok := r.TLS
    if !ok {
        http.Error(w, "No TLS connection", http.StatusBadRequest)
        return
    }

    // Get the client certificate chain
    certs := state.PeerCertificates
    if len(certs) == 0 {
        http.Error(w, "No client certificate", http.StatusBadRequest)
        return
    }

    // Validate the client certificate chain
    // Here, we simply check that the leaf certificate is signed by a trusted root CA
    // You can replace this with your own validation logic
    trustedCAs := x509.NewCertPool()
    pemCAs, err := ioutil.ReadFile("my-root-ca.pem")
    if err != nil {
        http.Error(w, "Failed to read root CA file", http.StatusInternalServerError)
        return
    }
    if !trustedCAs.AppendCertsFromPEM(pemCAs) {
        http.Error(w, "Failed to parse root CA file", http.StatusInternalServerError)
        return
    }
    opts := x509.VerifyOptions{
        Roots:         trustedCAs,
        CurrentTime:   time.Now(),
        DNSName:       "",
        Intermediates: x509.NewCertPool(),
    }
    if _, err := certs[0].Verify(opts); err != nil {
        http.Error(w, "Invalid client certificate", http.StatusBadRequest)
        return
    }

    // Client certificate is valid, do something with it...
}

/**
To retrieve the client's certificate and validate its authenticity using the crypto/tls package in Go, you 
can use the tls.ConnectionState struct that is available on the http.Request object after a successful TLS handshake.

In this example, we first retrieve the TLS connection state using r.TLS. We then check if the client provided a 
certificate chain, and if so, we retrieve it from the PeerCertificates field of the connection state.

Next, we validate the client certificate chain by checking that the leaf certificate is signed by a trusted root 
CA. We create a x509.CertPool containing the trusted root CA(s) and use it to configure an x509.VerifyOptions struct. 
We then call Verify() on the leaf certificate, passing in the VerifyOptions. If the certificate chain is valid, Verify() 
returns a *x509.Certificate representing the verified leaf certificate.

Finally, we can perform some action with the validated client certificate, such as logging information or authorizing 
access to a resource.

*/