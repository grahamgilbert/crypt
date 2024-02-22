package pref

import (
	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/pkg/errors"
)

type Pref struct {
	Runner utils.CmdRunner
}

type PrefInterface interface {
	Delete(prefName string) error
	GetString(prefName string) (string, error)
	GetBool(prefName string) (bool, error)
	GetInt(prefName string) (int, error)
	GetArray(prefName string) ([]string, error)
	SetString(prefName string, value string) error
	SetBool(prefName string, value bool) error
	SetInt(prefName string, value int) error
	SetArray(prefName string, prefValue []string) error
	Get(prefName string) (interface{}, error)
	Set(prefName string, value interface{}) error
}

// New creates a new Pref struct
func New() PrefInterface {
	return &Pref{
		Runner: &utils.ExecCmdRunner{},
	}
}

// Delete removes a preference from the system
func (p *Pref) Delete(prefName string) error {
	_, err := p.Runner.RunCmd("/usr/bin/defaults", "delete", BundleID, prefName)
	if err != nil {
		return errors.Wrapf(err, "failed to delete preference %s", prefName)
	}
	return nil
}

// GetString returns the value of a preference as a string
func (p *Pref) GetString(prefName string) (string, error) {
	value, err := p.Get(prefName)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get preference %s", prefName)
	}
	return value.(string), nil
}

// GetBool returns the value of a preference as a bool
func (p *Pref) GetBool(prefName string) (bool, error) {
	value, err := p.Get(prefName)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get preference %s", prefName)
	}
	if value == nil {
		return false, nil
	}
	return value.(bool), nil
}

// GetInt returns the value of a preference as an int
func (p *Pref) GetInt(prefName string) (int, error) {
	value, err := p.Get(prefName)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to get preference %s", prefName)
	}
	if value == nil {
		return 0, nil
	}
	return value.(int), nil
}

// GetArray returns the value of a preference as an array
func (p *Pref) GetArray(prefName string) ([]string, error) {
	value, err := p.Get(prefName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get preference %s", prefName)
	}
	if value == nil {
		return nil, nil
	}
	return value.([]string), nil
}

// SetString sets the value of a preference as a string
func (p *Pref) SetString(prefName string, value string) error {
	return p.Set(prefName, value)
}

// SetBool sets the value of a preference as a bool
func (p *Pref) SetBool(prefName string, value bool) error {
	return p.Set(prefName, value)
}

// SetInt sets the value of a preference as an int
func (p *Pref) SetInt(prefName string, value int) error {
	return p.Set(prefName, value)
}

// SetArray sets the value of a preference as an array
func (p *Pref) SetArray(prefName string, prefValue []string) error {
	return p.Set(prefName, prefValue)
}
