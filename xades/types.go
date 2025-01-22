package xades

import (
	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

type AlgorithmID string

func (id AlgorithmID) String() string {
	return string(id)
}

type Canonicalizer interface {
	Canonicalize(el *etree.Element) ([]byte, error)
	Algorithm() AlgorithmID
}

type c14N10ExclusiveCanonicalizer struct {
	prefixList string
	comments   bool
}

// Canonicalize transforms the input Element into a serialized XML document in canonical form.
func (c *c14N10ExclusiveCanonicalizer) Canonicalize(el *etree.Element) ([]byte, error) {
	err := etreeutils.TransformExcC14n(el, c.prefixList, c.comments)
	if err != nil {
		return nil, err
	}
	return canonicalSerialize(el)
}

func (c *c14N10ExclusiveCanonicalizer) Algorithm() AlgorithmID {
	if c.comments {
		return CanonicalXML10ExclusiveWithCommentsAlgorithmId
	}
	return CanonicalXML10ExclusiveAlgorithmId
}

func MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList string) Canonicalizer {
	return &c14N10ExclusiveCanonicalizer{
		prefixList: prefixList,
		comments:   false,
	}
}

func canonicalSerialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())

	//sortAttributesRecursively(doc.Root())

	doc.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}

	return doc.WriteToBytes()
}

func sortAttributesRecursively(el *etree.Element) {
	// Sortuj atrybuty bieżącego elementu
	el.SortAttrs()

	// Rekurencyjnie sortuj atrybuty w dzieciach
	for _, child := range el.ChildElements() {
		sortAttributesRecursively(child)
	}
}
