package checkin

type MockPrefV2 struct {
	ServerURL string
}

func (m *MockPrefV2) GetString(key string) (string, error) {
	return m.ServerURL, nil
}

func (m *MockPrefV2) SetString(key string, value string) error {
	m.ServerURL = value
	return nil
}

func (m *MockPrefV2) GetInt(key string) (int, error) {
	// not implemented yet. Just to satisty interface
	return 0, nil
}

func (m *MockPrefV2) SetInt(key string, value int) error {
	// not implemented yet. Just to satisty interface
	return nil
}

func (m *MockPrefV2) GetArray(key string) ([]string, error) {
	// not implemented yet. Just to satisty interface
	return nil, nil
}

func (m *MockPrefV2) SetArray(key string, value []string) error {
	// not implemented yet. Just to satisty interface
	return nil
}

func (m *MockPrefV2) Get(key string) (interface{}, error) {
	// not implemented yet. Just to satisty interface
	return nil, nil
}

func (m *MockPrefV2) Set(key string, value interface{}) error {
	// not implemented yet. Just to satisty interface
	return nil
}

func (m *MockPrefV2) Delete(key string) error {
	// not implemented yet. Just to satisty interface
	return nil
}

func (m *MockPrefV2) GetBool(key string) (bool, error) {
	// not implemented yet. Just to satisty interface
	return false, nil
}

func (m *MockPrefV2) SetBool(key string, value bool) error {
	// not implemented yet. Just to satisty interface
	return nil
}
