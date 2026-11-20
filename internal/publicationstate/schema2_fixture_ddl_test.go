package publicationstate

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const schema2FixtureDDLPath = "testdata/attempts-v2/generate/schema2.sql"

func TestSchema2FixtureDDLMatchesSchemaInventory(t *testing.T) {
	data, err := os.ReadFile(schema2FixtureDDLPath)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	lines := strings.Split(string(data), "\n")
	statements := make([]string, 0, len(lines))
	tables := 0
	indexes := 0
	names := make(map[string]struct{}, len(lines))
	for index, line := range lines {
		if line == "" && index == len(lines)-1 {
			continue
		}
		require.NotEmpty(t, line, "line %d is blank", index+1)
		require.Equal(t, line, strings.TrimSpace(line), "line %d is padded", index+1)
		require.True(t, strings.HasSuffix(line, ";"), "line %d is unterminated", index+1)
		statement := strings.TrimSuffix(line, ";")
		require.NotContains(t, statement, ";", "line %d holds more than one statement", index+1)
		var name string
		switch {
		case strings.HasPrefix(statement, "CREATE TABLE "):
			name = strings.SplitN(strings.TrimPrefix(statement, "CREATE TABLE "), " (", 2)[0]
			tables++
		case strings.HasPrefix(statement, "CREATE INDEX "):
			name = strings.SplitN(strings.TrimPrefix(statement, "CREATE INDEX "), " ON ", 2)[0]
			indexes++
		default:
			require.FailNowf(t, "non-CREATE statement", "line %d", index+1)
		}
		require.NotEmpty(t, name, "line %d has no object name", index+1)
		_, duplicate := names[name]
		require.False(t, duplicate, "object %s is duplicated", name)
		names[name] = struct{}{}
		statements = append(statements, statement)
	}
	inventory, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	assert.Len(t, statements, 17)
	assert.Equal(t, 15, tables)
	assert.Equal(t, 2, indexes)
	assert.Len(t, inventory.statements, 17)
	assert.Equal(t, inventory.statements, statements)
}
