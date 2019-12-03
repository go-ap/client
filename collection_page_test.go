package activitystreams

import (
	"reflect"
	"testing"
)

func TestCollectionPageNew(t *testing.T) {
	var testValue = ObjectID("test")

	c := CollectionNew(testValue)
	p := CollectionPageNew(c)
	if reflect.DeepEqual(p.Collection, c) {
		t.Errorf("Invalid collection parent '%v'", p.PartOf)
	}
	if p.PartOf != c.GetLink() {
		t.Errorf("Invalid collection '%v'", p.PartOf)
	}
}

func TestCollectionPage_Append(t *testing.T) {
	id := ObjectID("test")

	val := Object{ID: ObjectID("grrr")}

	c := CollectionNew(id)

	p := CollectionPageNew(c)
	p.Append(val)

	if p.PartOf != c.GetLink() {
		t.Errorf("Collection page should point to collection %q", c.GetLink())
	}
	if p.Count() != 1 {
		t.Errorf("Collection page of %q should have exactly one element", *p.GetID())
	}
	if !reflect.DeepEqual(p.Items[0], val) {
		t.Errorf("First item in Inbox is does not match %q", val.ID)
	}
}

func TestCollectionPage_UnmarshalJSON(t *testing.T) {
	p := CollectionPage{}

	dataEmpty := []byte("{}")
	p.UnmarshalJSON(dataEmpty)
	if p.ID != "" {
		t.Errorf("Unmarshaled object should have empty ID, received %q", p.ID)
	}
	if p.Type != "" {
		t.Errorf("Unmarshaled object should have empty Type, received %q", p.Type)
	}
	if p.AttributedTo != nil {
		t.Errorf("Unmarshaled object should have empty AttributedTo, received %q", p.AttributedTo)
	}
	if len(p.Name) != 0 {
		t.Errorf("Unmarshaled object should have empty Name, received %q", p.Name)
	}
	if len(p.Summary) != 0 {
		t.Errorf("Unmarshaled object should have empty Summary, received %q", p.Summary)
	}
	if len(p.Content) != 0 {
		t.Errorf("Unmarshaled object should have empty Content, received %q", p.Content)
	}
	if p.TotalItems != 0 {
		t.Errorf("Unmarshaled object should have empty TotalItems, received %d", p.TotalItems)
	}
	if len(p.Items) > 0 {
		t.Errorf("Unmarshaled object should have empty Items, received %v", p.Items)
	}
	if p.URL != nil {
		t.Errorf("Unmarshaled object should have empty URL, received %v", p.URL)
	}
	if !p.Published.IsZero() {
		t.Errorf("Unmarshaled object should have empty Published, received %q", p.Published)
	}
	if !p.StartTime.IsZero() {
		t.Errorf("Unmarshaled object should have empty StartTime, received %q", p.StartTime)
	}
	if !p.Updated.IsZero() {
		t.Errorf("Unmarshaled object should have empty Updated, received %q", p.Updated)
	}
	if p.PartOf != nil {
		t.Errorf("Unmarshaled object should have empty PartOf, received %q", p.PartOf)
	}
	if p.Current != nil {
		t.Errorf("Unmarshaled object should have empty Current, received %q", p.Current)
	}
	if p.First != nil {
		t.Errorf("Unmarshaled object should have empty First, received %q", p.First)
	}
	if p.Last != nil {
		t.Errorf("Unmarshaled object should have empty Last, received %q", p.Last)
	}
	if p.Next != nil {
		t.Errorf("Unmarshaled object should have empty Next, received %q", p.Next)
	}
	if p.Prev != nil {
		t.Errorf("Unmarshaled object should have empty Prev, received %q", p.Prev)
	}
}

func TestCollectionPage_Collection(t *testing.T) {
	id := ObjectID("test")

	c := CollectionNew(id)
	p := CollectionPageNew(c)

	if !reflect.DeepEqual(p.Collection(), p.Items) {
		t.Errorf("Collection items should be equal %v %v", p.Collection(), p.Items)
	}
}

func TestCollectionPage_Count(t *testing.T) {
	id := ObjectID("test")

	c := CollectionNew(id)
	p := CollectionPageNew(c)

	if p.TotalItems != 0 {
		t.Errorf("Empty object should have empty TotalItems, received %d", p.TotalItems)
	}
	if len(p.Items) > 0 {
		t.Errorf("Empty object should have empty Items, received %v", p.Items)
	}
	if p.Count() != uint(len(p.Items)) {
		t.Errorf("%T.Count() returned %d, expected %d", c, p.Count(), len(p.Items))
	}

	p.Append(IRI("test"))
	if p.TotalItems != 0 {
		t.Errorf("Empty object should have empty TotalItems, received %d", p.TotalItems)
	}
	if p.Count() != uint(len(p.Items)) {
		t.Errorf("%T.Count() returned %d, expected %d", c, p.Count(), len(p.Items))
	}
}

func TestToCollectionPage(t *testing.T) {
	t.Skipf("TODO")
}

func TestCollectionPage_Contains(t *testing.T) {
	t.Skipf("TODO")
}
