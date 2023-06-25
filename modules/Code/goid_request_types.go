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

type UserCreateRequest struct {
	Email string `json:"email"`
	Firstname string `json:"first"`
	Lastname string `json:"last"`
	Password string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
	AddressOne string `json:"address_1,omitempty"`	// Street
	AddressTwo string `json:"address_2,omitempty"`	// City
	RegionOne int `json:"region_1,omitempty"`	// Country (required)
	RegionTwo int `json:"region_2,omitempty"` // Region (state, province, canton)
	ZipCode string `json:"zip_code,omitempty"`	// (optional)
	SchoolId int `json:"school_id,omitempty"`
	Phone string `json:"phone,omitempty"`
}

type GenrateTokenRequest struct {
	UID int `json:"uid"`
}