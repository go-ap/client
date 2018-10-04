package activitypub

import (
	"reflect"
	"testing"
	"time"
)

func TestUpdateActivityNew(t *testing.T) {
	var testValue = ObjectID("test")
	var now time.Time

	c := UpdateActivityNew(testValue, nil, nil)
	now = time.Now()
	if c.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c.Activity.ID, testValue)
	}
	if c.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c.Activity.Type, UpdateType)
	}
	if now.Sub(c.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c.Published, now)
	}
}

func TestUpdateActivityNewWithApplication(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	a := ApplicationNew("some::app::")

	c1 := UpdateActivityNew(testValue, *a, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != a.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), a.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), a.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), a.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *a) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, Actor(*a))
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
	in := c1.Activity.Actor.(Application).Inbox.(*Inbox)
	if in.TotalItems != 1 {
		t.Errorf("Inbox collection of %q should have exactly one element, not %d", *c1.Activity.Actor.GetID(), in.TotalItems)
	}
	if len(in.OrderedItems) != 1 {
		t.Errorf("Inbox collection length of %q should have exactly one element, not %d", *c1.Activity.Actor.GetID(), len(in.OrderedItems))
	}
	if in.TotalItems != uint(len(in.OrderedItems)) {
		t.Errorf("Inbox collection length of %q should have same size as TotalItems, %d vs %d", *c1.Activity.Actor.GetID(), in.TotalItems, len(in.OrderedItems))
	}
	if !reflect.DeepEqual(in.OrderedItems[0].GetID(), n.GetID()) {
		t.Errorf("First item in Inbox is does not match %q", *n.GetID())
	}
}

func TestUpdateActivityNewWithGroup(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	g := GroupNew("users")

	c1 := UpdateActivityNew(testValue, *g, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != g.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), g.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), g.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), g.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *g) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, Actor(*g))
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
}

func TestUpdateActivityNewWithOrganization(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	o := OrganizationNew("users")

	c1 := UpdateActivityNew(testValue, *o, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != o.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), o.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), o.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), o.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *o) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, Actor(*o))
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
}

func TestUpdateActivityNewWithPerson(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	b := PersonNew("bob")

	c1 := UpdateActivityNew(testValue, *b, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != b.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), b.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), b.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), b.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *b) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, Actor(*b))
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
}

func TestUpdateActivityNewWithService(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	s := ServiceNew("::zz::")

	c1 := UpdateActivityNew(testValue, *s, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != s.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), s.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), s.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), s.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *s) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, Actor(*s))
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
}

func TestUpdateActivityNewWithActor(t *testing.T) {
	testValue := ObjectID("my:note")
	n := ObjectNew("my:note", NoteType)
	a := ActorNew("bob", ActorType)

	c1 := UpdateActivityNew(testValue, *a, n)
	now := time.Now()
	if c1.Activity.ID != testValue {
		t.Errorf("Activity Id '%v' different than expected '%v'", c1.Activity.ID, testValue)
	}
	if c1.Activity.Type != UpdateType {
		t.Errorf("Activity Type '%v' different than expected '%v'", c1.Activity.Type, UpdateType)
	}
	if now.Sub(c1.Published).Round(time.Millisecond) != 0 {
		t.Errorf("Published time '%v' different than expected '%v'", c1.Published, now)
	}
	if *c1.Activity.Actor.GetID() != a.ID {
		t.Errorf("Actor ID %q different than expected %q", *c1.Activity.Actor.GetID(), a.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Actor.GetID(), a.GetID()) {
		t.Errorf("Actor %#v different than expected %#v", c1.Activity.Actor.GetID(), a.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Actor, *a) {
		t.Errorf("Actor %#v\n\n different than expected\n\n %#v", c1.Activity.Actor, *a)
	}
	if *c1.Activity.Object.GetID() != n.ID {
		t.Errorf("GetID %q different than expected %q", *c1.Activity.Object.GetID(), n.ID)
	}
	if !reflect.DeepEqual(c1.Activity.Object.GetID(), n.GetID()) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object.GetID(), n.GetID())
	}
	if !reflect.DeepEqual(c1.Activity.Object, n) {
		t.Errorf("GetID %#v different than expected %#v", c1.Activity.Object, n)
	}
}