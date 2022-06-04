package client

import (
	"context"
	"fmt"
	"net/url"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
)

type FilterFn func() url.Values

type PubGetter interface {
	Inbox(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Outbox(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Following(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Followers(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Likes(ctx context.Context, object vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Liked(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Replies(ctx context.Context, object vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error)
	Collection(ctx context.Context, i vocab.IRI, filters ...FilterFn) (vocab.CollectionInterface, error)

	Actor(ctx context.Context, iri vocab.IRI) (*vocab.Actor, error)
	Activity(ctx context.Context, iri vocab.IRI) (*vocab.Activity, error)
	Object(ctx context.Context, iri vocab.IRI) (*vocab.Object, error)
}

type PubSubmitter interface {
	ToOutbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error)
	ToInbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error)
}

type PubClient interface {
	PubGetter
	PubSubmitter
}

// Inbox
func (c C) Inbox(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, inbox(actor, filters...))
}

// Outbox
func (c C) Outbox(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, outbox(actor, filters...))
}

// Following
func (c C) Following(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, following(actor, filters...))
}

// Followers
func (c C) Followers(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, followers(actor, filters...))
}

// Likes
func (c C) Likes(ctx context.Context, object vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, likes(object, filters...))
}

// Liked
func (c C) Liked(ctx context.Context, actor vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, liked(actor, filters...))
}

// Replies
func (c C) Replies(ctx context.Context, object vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, replies(object, filters...))
}

// Shares
func (c C) Shares(ctx context.Context, object vocab.Item, filters ...FilterFn) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, shares(object, filters...))
}

// Collection
func (c C) Collection(ctx context.Context, i vocab.IRI, filters ...FilterFn) (vocab.CollectionInterface, error) {
	return c.collection(ctx, iri(i, filters...))
}

// Actor
func (c C) Actor(ctx context.Context, iri vocab.IRI) (*vocab.Actor, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Actor: %s", iri)
	}
	var person *vocab.Actor
	vocab.OnActor(it, func(p *vocab.Actor) error {
		person = p
		return nil
	})
	return person, nil
}

// Activity
func (c C) Activity(ctx context.Context, iri vocab.IRI) (*vocab.Activity, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Activity: %s", iri)
	}
	var activity *vocab.Activity
	vocab.OnActivity(it, func(a *vocab.Activity) error {
		activity = a
		return nil
	})
	return activity, nil
}

// Object
func (c C) Object(ctx context.Context, iri vocab.IRI) (*vocab.Object, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Object: %s", iri)
	}
	var object *vocab.Object
	vocab.OnObject(it, func(o *vocab.Object) error {
		object = o
		return nil
	})
	return object, nil
}

func validateIRIForRequest(i vocab.IRI) error {
	u, err := i.URL()
	if err != nil {
		return err
	}
	if u.Host == "" {
		return errors.Newf("Host is empty")
	}
	return nil
}

func (c C) ToOutbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	var iri vocab.IRI
	vocab.OnActivity(a, func(a *vocab.Activity) error {
		iri = outbox(a.Actor)
		return nil
	})
	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Outbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
}

func (c C) ToInbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	var iri vocab.IRI
	vocab.OnActivity(a, func(a *vocab.Activity) error {
		iri = inbox(a.Actor)
		return nil
	})

	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Inbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
}

func (c C) collection(ctx context.Context, i vocab.IRI) (vocab.CollectionInterface, error) {
	it, err := c.CtxLoadIRI(ctx, i)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load IRI: %s", i)
	}
	if vocab.IsNil(it) {
		return nil, errors.Newf("Unable to load IRI, nil item: %s", i)
	}
	var col vocab.CollectionInterface
	typ := it.GetType()
	if !vocab.CollectionTypes.Contains(it.GetType()) {
		return nil, errors.Errorf("Response item type is not a valid collection: %s", typ)
	}
	var ok bool
	switch typ {
	case vocab.CollectionType:
		col, ok = it.(*vocab.Collection)
	case vocab.CollectionPageType:
		col, ok = it.(*vocab.CollectionPage)
	case vocab.OrderedCollectionType:
		col, ok = it.(*vocab.OrderedCollection)
	case vocab.OrderedCollectionPageType:
		col, ok = it.(*vocab.OrderedCollectionPage)
	}
	if !ok {
		return nil, errors.Errorf("Unable to convert item type %s to any of the collection types", typ)
	}
	return col, nil
}
func (c C) object(ctx context.Context, i vocab.IRI) (vocab.Item, error) {
	return c.CtxLoadIRI(ctx, i)
}

func rawFilterQuery(f ...FilterFn) string {
	if len(f) == 0 {
		return ""
	}
	q := make(url.Values)
	for _, ff := range f {
		qq := ff()
		for k, v := range qq {
			q[k] = append(q[k], v...)
		}
	}
	if len(q) == 0 {
		return ""
	}

	return "?" + q.Encode()
}
func iri(i vocab.IRI, f ...FilterFn) vocab.IRI {
	return vocab.IRI(fmt.Sprintf("%s%s", i, rawFilterQuery(f...)))
}
func inbox(a vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Inbox.IRI(a), f...)
}
func outbox(a vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Outbox.IRI(a), f...)
}
func following(a vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Following.IRI(a), f...)
}
func followers(a vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Followers.IRI(a), f...)
}
func liked(a vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Liked.IRI(a), f...)
}
func likes(o vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Likes.IRI(o), f...)
}
func shares(o vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Shares.IRI(o), f...)
}
func replies(o vocab.Item, f ...FilterFn) vocab.IRI {
	return iri(vocab.Replies.IRI(o), f...)
}
func validateActor(a vocab.Item) error {
	if vocab.IsNil(a) {
		return errors.Errorf("Actor is nil")
	}
	if a.IsObject() && !vocab.ActorTypes.Contains(a.GetType()) {
		return errors.Errorf("Invalid Actor type %s", a.GetType())
	}
	return nil
}
func validateObject(o vocab.Item) error {
	if vocab.IsNil(o) {
		return errors.Errorf("object is nil")
	}
	if o.IsObject() && !vocab.ObjectTypes.Contains(o.GetType()) {
		return errors.Errorf("invalid Object type %q", o.GetType())
	}
	return nil
}
