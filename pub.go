package client

import (
	"context"
	"slices"

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
	it, err := c.loadCtx(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to load actor")
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
	it, err := c.loadCtx(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to load activity")
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
	it, err := c.loadCtx(ctx, iri)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to load object")
	}
	var object *vocab.Object
	err = vocab.OnObject(it, func(o *vocab.Object) error {
		object = o
		return nil
	})
	return object, err
}

type iriGenFn func(vocab.Item, ...filters.Check) vocab.IRI

func ActivityActorTargetCollections(act vocab.Item, colFn iriGenFn) (vocab.IRIs, error) {
	if colFn == nil {
		return nil, errors.Newf("invalid collection IRI function")
	}
	var targetIRIs vocab.IRIs
	err := vocab.OnIntransitiveActivity(act, func(a *vocab.IntransitiveActivity) error {
		err := vocab.OnItem(a.Actor, func(act vocab.Item) error {
			// NOTE(marius): apply the colFn function to the actor to generate the target collection IRI.
			targetIRIs = append(targetIRIs, colFn(act))
			return nil
		})
		// NOTE(marius): normalize the target collection IRIs.
		switch {
		case vocab.IsItemCollection(a.Actor):
			if actors, err := vocab.ToItemCollection(a.Actor); err == nil {
				a.Actor = actors.IRIs()
			}
		case !vocab.IsIRI(a.Actor):
			a.Actor = a.Actor.GetLink()
		}
		return err
	})
	if err != nil {
		return nil, errors.Annotatef(err, "object of type %T is not an activity", act)
	}
	inValidIRIFn := func(iri vocab.IRI) bool {
		return validateIRIForRequest(iri) != nil
	}
	return slices.DeleteFunc(targetIRIs, inValidIRIFn), nil
}

// ToOutbox dispatches an Activity to its Actor's Outbox.
// It is the simplest mechanism to dispatch an ActivityPub Social API activity.
func (c C) ToOutbox(ctx context.Context, act vocab.Item) (vocab.IRI, vocab.Item, error) {
	outboxes, err := ActivityActorTargetCollections(act, outbox)
	if err != nil {
		return "", nil, err
	}
	return c.CtxToCollection(ctx, act, outboxes...)
}

func (c C) ToInbox(ctx context.Context, act vocab.Item) (vocab.IRI, vocab.Item, error) {
	outboxes, err := ActivityActorTargetCollections(act, inbox)
	if err != nil {
		return "", nil, err
	}
	return c.CtxToCollection(ctx, act, outboxes...)
}

func validateIRIForRequest(i vocab.IRI) error {
	u, err := i.URL()
	if err != nil {
		return err
	}
	if u.Host == "" {
		return errors.Newf("IRI host is empty")
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
		return nil, errors.Annotatef(err, "unable to load")
	}
	if vocab.IsNil(it) {
		return nil, errors.Newf("unable to load IRI, nil item: %s", i)
	}
	var col vocab.CollectionInterface

	typ := it.GetType()
	if !vocab.CollectionTypes.Match(it.GetType()) {
		return nil, errors.Errorf("response item type is not a valid collection: %q", typ)
	}

	switch {
	case vocab.CollectionOfItems.Match(typ):
		col, err = vocab.ToItemCollection(it)
	case vocab.CollectionOfIRIs.Match(typ):
		// NOTE(marius): this probably is not needed, as the Unmarshaling of an array results in an ItemCollection,
		// even if its elements are all IRIs.
		col, err = vocab.ToIRIs(it)
	case vocab.CollectionType.Match(typ):
		col, err = vocab.ToCollection(it)
	case vocab.CollectionPageType.Match(typ):
		col, err = vocab.ToCollectionPage(it)
	case vocab.OrderedCollectionType.Match(typ):
		col, err = vocab.ToOrderedCollection(it)
	case vocab.OrderedCollectionPageType.Match(typ):
		col, err = vocab.ToOrderedCollectionPage(it)
	}
	if err != nil {
		return nil, errors.Annotatef(err, "unable to convert item type %q to any of the collection types", typ)
	}
	return col, nil
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
		return errors.Errorf("item is nil")
	}
	if a.IsObject() && !vocab.ActorTypes.Match(a.GetType()) {
		return errors.Errorf("invalid Actor type %v", a.GetType())
	}
	return nil
}

func validateObject(it vocab.Item) error {
	if vocab.IsNil(it) {
		return errors.Errorf("item is nil")
	}
	if it.IsObject() && !vocab.ObjectTypes.Match(it.GetType()) {
		return errors.Errorf("invalid Object type %v", it.GetType())
	}
	return nil
}
