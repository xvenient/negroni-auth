package auth

import "github.com/nabeken/negroni-auth/datastore"

// NewSimpleBasic returns *datastore.Simple builded from userid, password.
func NewSimpleBasic(userId, password string) (*datastore.Simple, error) {
	hashedPassword, err := Hash(password)
	if err != nil {
		return nil, err
	}

	return &datastore.Simple{
		Key:   userId,
		Value: hashedPassword,
	}, nil
}
