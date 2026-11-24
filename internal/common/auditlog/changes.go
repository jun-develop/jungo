package auditlog

import (
	"reflect"

	"github.com/jun-develop/junkit/stringx"
)

// Changes returns the non-nil pointer fields of struct v, keyed in snake_case; `audit:"-"` skips a field.
func Changes(v any) map[string]any {
	changes := map[string]any{}
	rv := reflect.Indirect(reflect.ValueOf(v))
	for i := range rv.NumField() {
		field, value := rv.Type().Field(i), rv.Field(i)
		if !field.IsExported() || field.Tag.Get("audit") == "-" || value.Kind() != reflect.Pointer || value.IsNil() {
			continue
		}

		changes[stringx.ToSnake(field.Name)] = value.Elem().Interface()
	}

	return changes
}
