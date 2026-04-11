package client

import (
	"context"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
)

type PubGetter interface {
	Inbox(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Outbox(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Following(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Followers(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Likes(ctx context.Context, object vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Liked(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Replies(ctx context.Context, object vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error)
	Collection(ctx context.Context, i vocab.IRI, ff ...filters.Check) (vocab.CollectionInterface, error)

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

// Inbox fetches the inbox collection of the actor Item. It applies filters to the received collection object.
func (c C) Inbox(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, inbox(actor, ff...))
}

// Outbox fetches the outbox collection of the actor Item. It applies filters to the received collection object.
func (c C) Outbox(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, outbox(actor, ff...))
}

// Following fetches the following collection of the actor Item. It applies filters to the received collection object.
func (c C) Following(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, following(actor, ff...))
}

// Followers fetches the followers collection of the actor Item. It applies filters to the received collection object.
func (c C) Followers(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, followers(actor, ff...))
}

// Likes fetches the likes collection of the object Item. It applies filters to the received collection object.
func (c C) Likes(ctx context.Context, object vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, likes(object, ff...))
}

// Liked fetches the liked collection of the actor Item. It applies filters to the received collection object.
func (c C) Liked(ctx context.Context, actor vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	return c.collection(ctx, liked(actor, ff...))
}

// Replies fetches the replies collection of the object Item. It applies filters to the received collection object.
func (c C) Replies(ctx context.Context, object vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, replies(object, ff...))
}

// Shares fetches the shares collection of the object Item. It applies filters to the received collection object.
func (c C) Shares(ctx context.Context, object vocab.Item, ff ...filters.Check) (vocab.CollectionInterface, error) {
	if err := validateObject(object); err != nil {
		return nil, err
	}
	return c.collection(ctx, shares(object, ff...))
}

// Collection fetches the iri [vocab.IRI] as a collection. It applies filters to the received object.
func (c C) Collection(ctx context.Context, iri vocab.IRI, ff ...filters.Check) (vocab.CollectionInterface, error) {
	return c.collection(ctx, irif(iri, ff...))
}

// Actor dereferences the iri [vocab.IRI] as an actor object.
func (c C) Actor(ctx context.Context, iri vocab.IRI) (*vocab.Actor, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Actor: %s", iri)
	}
	var actor *vocab.Actor
	err = vocab.OnActor(it, func(p *vocab.Actor) error {
		actor = p
		return nil
	})
	return actor, err
}

// Activity dereferences the iri [vocab.IRI] as an activity object.
func (c C) Activity(ctx context.Context, iri vocab.IRI) (*vocab.Activity, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load Activity: %s", iri)
	}
	var activity *vocab.Activity
	err = vocab.OnActivity(it, func(a *vocab.Activity) error {
		activity = a
		return nil
	})
	return activity, err
}

// Object dereferences the iri [vocab.IRI] as an object.
func (c C) Object(ctx context.Context, iri vocab.IRI) (*vocab.Object, error) {
	it, err := c.object(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load IRI: %s", iri)
	}
	var object *vocab.Object
	err = vocab.OnObject(it, func(o *vocab.Object) error {
		object = o
		return nil
	})
	return object, err
}

func (c C) ToOutbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	var iri vocab.IRI
	_ = vocab.OnIntransitiveActivity(a, func(a *vocab.IntransitiveActivity) error {
		// TODO(marius): this needs updating to work with an Actor that is an IRIs or ItemCollection
		iri = outbox(a.Actor)
		if !vocab.IsIRI(a.Actor) {
			a.Actor = a.Actor.GetLink()
		}
		return nil
	})
	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Outbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
}

func (c C) ToInbox(ctx context.Context, a vocab.Item) (vocab.IRI, vocab.Item, error) {
	var iri vocab.IRI
	_ = vocab.OnIntransitiveActivity(a, func(a *vocab.IntransitiveActivity) error {
		// TODO(marius): this needs updating to work with an Actor that is an IRIs or ItemCollection
		iri = inbox(a.Actor)
		if !vocab.IsIRI(a.Actor) {
			a.Actor = a.Actor.GetLink()
		}
		return nil
	})

	if err := validateIRIForRequest(iri); err != nil {
		return "", nil, errors.Annotatef(err, "Invalid Inbox IRI")
	}
	return c.CtxToCollection(ctx, iri, a)
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

func rawFilterQuery(f ...filters.Check) string {
	if len(f) == 0 {
		return ""
	}
	return "?" + filters.ToValues(f...).Encode()
}

func (c C) collection(ctx context.Context, i vocab.IRI) (vocab.CollectionInterface, error) {
	it, err := c.CtxLoadIRI(ctx, i)
	if err != nil {
		return nil, errors.Annotatef(err, "Unable to load IRI: %q", i)
	}
	if vocab.IsNil(it) {
		return nil, errors.Newf("Unable to load IRI, nil item: %q", i)
	}
	var col vocab.CollectionInterface

	typ := it.GetType()
	if !vocab.CollectionTypes.Match(it.GetType()) {
		return nil, errors.Errorf("Response item type is not a valid collection: %q", typ)
	}
	var ok bool
	switch {
	case vocab.CollectionType.Match(typ):
		col, ok = it.(*vocab.Collection)
	case vocab.CollectionPageType.Match(typ):
		col, ok = it.(*vocab.CollectionPage)
	case vocab.OrderedCollectionType.Match(typ):
		col, ok = it.(*vocab.OrderedCollection)
	case vocab.OrderedCollectionPageType.Match(typ):
		col, ok = it.(*vocab.OrderedCollectionPage)
	}
	if !ok {
		return nil, errors.Errorf("Unable to convert item type %q to any of the collection types", typ)
	}
	return col, nil
}

func (c C) object(ctx context.Context, i vocab.IRI) (vocab.Item, error) {
	return c.CtxLoadIRI(ctx, i)
}

func irif(i vocab.IRI, f ...filters.Check) vocab.IRI {
	return vocab.IRI(string(i) + rawFilterQuery(f...))
}

func inbox(a vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Inbox.IRI(a), f...)
}

func outbox(a vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Outbox.IRI(a), f...)
}

func following(a vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Following.IRI(a), f...)
}

func followers(a vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Followers.IRI(a), f...)
}

func liked(a vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Liked.IRI(a), f...)
}

func likes(o vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Likes.IRI(o), f...)
}

func shares(o vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Shares.IRI(o), f...)
}

func replies(o vocab.Item, f ...filters.Check) vocab.IRI {
	return irif(vocab.Replies.IRI(o), f...)
}

func validateActor(a vocab.Item) error {
	if vocab.IsNil(a) {
		return errors.Errorf("Actor is nil")
	}
	if a.IsObject() && !vocab.ActorTypes.Match(a.GetType()) {
		return errors.Errorf("Invalid Actor type %s", a.GetType())
	}
	return nil
}

func validateObject(o vocab.Item) error {
	if vocab.IsNil(o) {
		return errors.Errorf("object is nil")
	}
	if o.IsObject() && !vocab.ObjectTypes.Match(o.GetType()) {
		return errors.Errorf("invalid Object type %q", o.GetType())
	}
	return nil
}
