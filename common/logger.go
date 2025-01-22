package common

import (
	"fmt"
	"github.com/beevik/etree"
)

type Logger interface {
	Debug(string)
	Info(string)
	Error(string)
}

func printXml(el *etree.Element) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	s, err := doc.WriteToString()
	if err != nil {
		fmt.Printf("failed to serialize XML: %v", err)
	}

	fmt.Printf("`%s`\n", s)
}
