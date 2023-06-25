package goid

// Struct representing a user record in the database
type User struct {
    ID    int
	Name string
    Email  string
    RegionOne string
    RegionTwo string
	Password []byte
    Token string
    Phone string
}