package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMutator(t *testing.T) {
	tests := []struct {
		name    string
		typ     string
		wantErr bool
	}{
		{name: "jsonPath", typ: "jsonPath", wantErr: false},
		{name: "yamlPath", typ: "yamlPath", wantErr: false},
		{name: "tomlKey", typ: "tomlKey", wantErr: false},
		{name: "regexReplace", typ: "regexReplace", wantErr: false},
		{name: "unknown", typ: "foobar", wantErr: true},
		{name: "empty", typ: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := GetMutator(tt.typ)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, m)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}
		})
	}
}

func TestValidMutationTypes(t *testing.T) {
	types := ValidMutationTypes()
	assert.GreaterOrEqual(t, len(types), 4)
	assert.Contains(t, types, "jsonPath")
	assert.Contains(t, types, "yamlPath")
	assert.Contains(t, types, "tomlKey")
	assert.Contains(t, types, "regexReplace")
}
