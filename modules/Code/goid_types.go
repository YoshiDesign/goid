package goid

type LoginRequest struct {
	Email string `json:"email"`
	Password  string    `json:"password"`
}

type LogoutRequest struct {
	Email string `json:"email"`
}

type VerifyRequest struct {
	Email string `json:"email"`
	Token  string    `json:"token"`
}