package mock

import (
	"fmt"
	"npcc/core/config"
	"npcc/core/identity"
)

type MockLog struct {
	Name string
}

func (l *MockLog) Debug(args ...interface{}) {
	fmt.Println(args...)
}
func (l *MockLog) Debugf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (l *MockLog) Info(args ...interface{}) {
	fmt.Println(args...)
}

func (l *MockLog) Infof(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (l *MockLog) Warn(args ...interface{}) {
	fmt.Println(args...)
}

func (l *MockLog) Warnf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (l *MockLog) Error(args ...interface{}) {
	fmt.Println(args...)
}

func (l *MockLog) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func GetMockLogger(name string) *MockLog {
	return &MockLog{name}
}

type MockID struct{}

func (id *MockID) InitID(cf *config.LocalConfig) error {
	return nil
}
func (id *MockID) Sign(data []byte, opts *identity.SignOpts) ([]byte, error) {
	return nil, nil
}
func (id *MockID) Verify(data []byte, sig []byte, opts *identity.SignOpts) (bool, error) {
	return true, nil
}
func (id *MockID) PublicKey() identity.Key {
	return &identity.ECDSAPublicKey{}
}
