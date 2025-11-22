package kfilters

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

var socketCapabilities = rules.FieldCapabilities{
	{
		Field:       "socket.type",
		TypeBitmask: eval.ScalarValueType | eval.BitmaskValueType,
	},
}

func socketKFiltersGetter(approvers rules.Approvers) (KFilters, []eval.Field, error) {
	var (
		kfilters     []kFilter
		fieldHandled []eval.Field
	)

	for field, values := range approvers {
		switch field {
		case "socket.type":
			kfilter, err := getEnumsKFilters("socket_type_approvers", uintValues[uint64](values)...)
			if err != nil {
				return nil, nil, err
			}
			kfilters = append(kfilters, kfilter)
			fieldHandled = append(fieldHandled, field)
		}
	}
	return newKFilters(kfilters...), fieldHandled, nil
}
