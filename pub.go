package client

import (
	"context"
	"fmt"
	"net/url"

	pub "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/handlers"
)

type FilterFn func() url.Values

type PubGetter interface {
	Inbox(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Outbox(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Following(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Followers(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Likes(ctx context.Context, object pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Liked(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Replies(ctx context.Context, object pub.Item, filters ...FilterFn) (pub.CollectionInterface, error)
	Collection(ctx context.Context, i pub.IRI, filters ...FilterFn) (pub.CollectionInterface, error)

	Actor(ctx context.Context, iri pub.IRI) (*pub.Actor, error)
	Activity(ctx context.Context, iri pub.IRI) (*pub.Activity, error)
	Object(ctx context.Context, iri pub.IRI) (*pub.Object, error)
}

type PubSubmitter interface {
	ToOutbox(ctx context.Context, a pub.Item) (pub.IRI, pub.Item, error)
	ToInbox(ctx context.Context, a pub.Item) (pub.IRI, pub.Item, error)
}

type PubClient interface {
	PubGetter
	PubSubmitter
}

// Inbox
func (c C) Inbox(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, inbox(actor, filters...))
}

// Outbox
func (c C) Outbox(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, outbox(actor, filters...))
}

// Following
func (c C) Following(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, following(actor, filters...))
}

// Followers
func (c C) Followers(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, followers(actor, filters...))
}

// Likes
func (c C) Likes(ctx context.Context, object pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, likes(object, filters...))
}

// Liked
func (c C) Liked(ctx context.Context, actor pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, liked(actor, filters...))
}

// Replies
func (c C) Replies(ctx context.Context, object pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, replies(object, filters...))
}

// Shares
func (c C) Shares(ctx context.Context, object pub.Item, filters ...FilterFn) (pub.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, shares(object, filters...))
}

// Collection
func (c C) Collection(ctx context.Context, i pub.IRI, filters ...FilterFn) (pub.CollectionInterface, error) {
	return c.collection(ctx, iri(i, filters...))
}

// Actor
func (c C) Actor(ctx context.Context, iri pub.IRI) (*pub.Actor, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Actor: %s", iri)
	}
	var person *pub.Actor
	pub.OnActor(it, func(p *pub.Actor) error {
		person = p
		return nil
	})
	return person, nil
}

// Activity
func (c C) Activity(ctx context.Context, iri pub.IRI) (*pub.Activity, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Activity: %s", iri)
	}
	var activity *pub.Activity
	pub.OnActivity(it, func(a *pub.Activity) error {
		activity = a
		return nil
	})
	return activity, nil
}

// Object
func (c C) Object(ctx context.Context, iri pub.IRI) (*pub.Object, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Object: %s", iri)
	}
	var object *pub.Object
	pub.OnObject(it, func(o *pub.Object) error {
		object = o
		return nil
	})
	return object, nil
}

func validateIRIForRequest(i pub.IRI) error {
	u, err := i.URL()
	if err != nil {
		return err
	}
	if u.Host == "" {
		return errors.Newf("Host is empty")
	}
	return nil
}

func (c C) ToOutbox(ctx context.Context, a pub.Item) (pub.IRI, pub.Item, error) {
	var iri pub.IRI
	pub.OnActivity(a, func(a *pub.Activity) error {
		iri = outbox(a.Actor)
		return nil
	})
	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Outbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
}

func (c C) ToInbox(ctx context.Context, a pub.Item) (pub.IRI, pub.Item, error) {
	var iri pub.IRI
	pub.OnActivity(a, func(a *pub.Activity) error {
		iri = inbox(a.Actor)
		return nil
	})

	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Inbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
}

func (c C) collection(ctx context.Context, i pub.IRI) (pub.CollectionInterface, error) {
	it, err := c.CtxLoadIRI(ctx, i)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load IRI: %s", i)
	}
	if it == nil {
		return nil, errors.Newf("Unable to load IRI, nil item: %s", i)
	}
	var col pub.CollectionInterface
	typ := it.GetType()
	if !pub.CollectionTypes.Contains(it.GetType()) {
		return nil, errors.Errorf("Response item type is not a valid collection: %s", typ)
	}
	var ok bool
	switch typ {
	case pub.CollectionType:
		col, ok = it.(*pub.Collection)
	case pub.CollectionPageType:
		col, ok = it.(*pub.CollectionPage)
	case pub.OrderedCollectionType:
		col, ok = it.(*pub.OrderedCollection)
	case pub.OrderedCollectionPageType:
		col, ok = it.(*pub.OrderedCollectionPage)
	}
	if !ok {
		return nil, errors.Errorf("Unable to convert item type %s to any of the collection types", typ)
	}
	return col, nil
}
func (c C) object(ctx context.Context, i pub.IRI) (pub.Item, error) {
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
func iri(i pub.IRI, f ...FilterFn) pub.IRI {
	return pub.IRI(fmt.Sprintf("%s%s", i, rawFilterQuery(f...)))
}
func inbox(a pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Inbox.IRI(a), f...)
}
func outbox(a pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Outbox.IRI(a), f...)
}
func following(a pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Following.IRI(a), f...)
}
func followers(a pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Followers.IRI(a), f...)
}
func liked(a pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Liked.IRI(a), f...)
}
func likes(o pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Likes.IRI(o), f...)
}
func shares(o pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Shares.IRI(o), f...)
}
func replies(o pub.Item, f ...FilterFn) pub.IRI {
	return iri(handlers.Replies.IRI(o), f...)
}
func validateActor(a pub.Item) error {
	if a == nil {
		return errors.Errorf("Actor is nil")
	}
	if a.IsObject() && !pub.ActorTypes.Contains(a.GetType()) {
		return errors.Errorf("Invalid Actor type %s", a.GetType())
	}
	return nil
}
func validateObject(o pub.Item) error {
	if o == nil {
		return errors.Errorf("object is nil")
	}
	if o.IsObject() && !pub.ObjectTypes.Contains(o.GetType()) {
		return errors.Errorf("invalid Object type %q", o.GetType())
	}
	return nil
}

