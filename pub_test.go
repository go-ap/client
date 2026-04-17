package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/google/go-cmp/cmp"
)

func Test_irif(t *testing.T) {
	type args struct {
		i vocab.IRI
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "empty filters",
			args: args{
				i: "http://example.com",
			},
			want: "http://example.com",
		},
		{
			name: "with maxItems",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.WithMaxCount(2)},
			},
			want: "http://example.com?maxItems=2",
		},
		{
			name: "with after",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.After(filters.SameID("http://social.example.com/jdoe"))},
			},
			want: "http://example.com?after=http%3A%2F%2Fsocial.example.com%2Fjdoe",
		},
		{
			name: "with type+name",
			args: args{
				i: "http://example.com",
				f: []filters.Check{filters.HasType("test"), filters.NameIs("jdoe")},
			},
			// NOTE(marius): I am not sure yet, what in the url.Values logic makes this always return in this order
			want: "http://example.com?name=jdoe&type=test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := irif(tt.args.i, tt.args.f...); got != tt.want {
				t.Errorf("irif() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateObject(t *testing.T) {
	tests := []struct {
		name    string
		it      vocab.Item
		wantErr error
	}{
		{
			name:    "empty",
			it:      nil,
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "empty type object",
			it:      &vocab.Object{},
			wantErr: errors.Newf("invalid Object type <nil>"),
		},
		{
			name:    "wrong type object",
			it:      &vocab.Object{Type: vocab.UpdateType},
			wantErr: errors.Newf("invalid Object type Update"),
		},
		{
			name: "good type object",
			it:   &vocab.Object{Type: vocab.ImageType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateObject(tt.it); !cmp.Equal(tt.wantErr, err, EquateWeakErrors) {
				t.Errorf("validateObject() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
		})
	}
}

func Test_validateActor(t *testing.T) {
	tests := []struct {
		name    string
		it      vocab.Item
		wantErr error
	}{
		{
			name:    "empty",
			it:      nil,
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "empty type object",
			it:      &vocab.Object{},
			wantErr: errors.Newf("invalid Actor type <nil>"),
		},
		{
			name:    "wrong type object",
			it:      &vocab.Object{Type: vocab.UpdateType},
			wantErr: errors.Newf("invalid Actor type Update"),
		},
		{
			name: "good type object",
			it:   &vocab.Object{Type: vocab.PersonType},
		},
		{
			name: "good type actor",
			it:   &vocab.Actor{Type: vocab.GroupType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateActor(tt.it); !cmp.Equal(tt.wantErr, err, EquateWeakErrors) {
				t.Errorf("validateActor() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
		})
	}
}

func Test_replies(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from object ID",
			args: args{
				o: vocab.Object{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/replies",
		},
		{
			name: "from object property",
			args: args{
				o: vocab.Object{ID: "http://example.com", Replies: vocab.IRI("http://example.com/custom-replies")},
				f: nil,
			},
			want: "http://example.com/custom-replies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replies(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("replies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_shares(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from object ID",
			args: args{
				o: vocab.Object{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/shares",
		},
		{
			name: "from object property",
			args: args{
				o: vocab.Object{ID: "http://example.com", Shares: vocab.IRI("http://example.com/custom-shares")},
				f: nil,
			},
			want: "http://example.com/custom-shares",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shares(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("shares() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_likes(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from object ID",
			args: args{
				o: vocab.Object{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/likes",
		},
		{
			name: "from object property",
			args: args{
				o: vocab.Object{ID: "http://example.com", Likes: vocab.IRI("http://example.com/custom-likes")},
				f: nil,
			},
			want: "http://example.com/custom-likes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := likes(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("likes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_liked(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from actor ID",
			args: args{
				o: vocab.Actor{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/liked",
		},
		{
			name: "from actor property",
			args: args{
				o: vocab.Actor{ID: "http://example.com", Liked: vocab.IRI("http://example.com/custom-liked")},
				f: nil,
			},
			want: "http://example.com/custom-liked",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := liked(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("liked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_followers(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from actor ID",
			args: args{
				o: vocab.Actor{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/followers",
		},
		{
			name: "from Actor property",
			args: args{
				o: vocab.Actor{ID: "http://example.com", Followers: vocab.IRI("http://example.com/custom-followers")},
				f: nil,
			},
			want: "http://example.com/custom-followers",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := followers(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("followers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_following(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from actor ID",
			args: args{
				o: vocab.Actor{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/following",
		},
		{
			name: "from actor property",
			args: args{
				o: vocab.Actor{ID: "http://example.com", Following: vocab.IRI("http://example.com/custom-following")},
				f: nil,
			},
			want: "http://example.com/custom-following",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := following(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("following() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_outbox(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from actor ID",
			args: args{
				o: vocab.Actor{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/outbox",
		},
		{
			name: "from actor property",
			args: args{
				o: vocab.Actor{ID: "http://example.com", Outbox: vocab.IRI("http://example.com/custom-outbox")},
				f: nil,
			},
			want: "http://example.com/custom-outbox",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outbox(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("outbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_inbox(t *testing.T) {
	type args struct {
		o vocab.Item
		f []filters.Check
	}
	tests := []struct {
		name string
		args args
		want vocab.IRI
	}{
		{
			name: "empty",
			args: args{},
			want: "",
		},
		{
			name: "from actor ID",
			args: args{
				o: vocab.Actor{ID: "http://example.com"},
				f: nil,
			},
			want: "http://example.com/inbox",
		},
		{
			name: "from actor property",
			args: args{
				o: vocab.Actor{ID: "http://example.com", Inbox: vocab.IRI("http://example.com/custom-inbox")},
				f: nil,
			},
			want: "http://example.com/custom-inbox",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inbox(tt.args.o, tt.args.f...); got != tt.want {
				t.Errorf("inbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateIRIForRequest(t *testing.T) {
	tests := []struct {
		name    string
		i       vocab.IRI
		wantErr error
	}{
		{
			name:    "empty",
			i:       "",
			wantErr: errors.Newf("empty IRI"),
		},
		{
			name:    "no host",
			i:       "/test",
			wantErr: errors.Newf("IRI host is empty"),
		},
		{
			name:    "valid",
			i:       "http://example.com",
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateIRIForRequest(tt.i); !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("validateIRIForRequest() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
			}
		})
	}
}

func ctxLogFn(t *testing.T) CtxLogFn {
	return func(ctx ...Ctx) LogFn {
		return func(s string, a ...any) {
			cc := make(lw.Ctx)
			for _, c := range ctx {
				for k, v := range c {
					cc[k] = v
				}
			}
			t.Log(fmt.Sprintf("%s %v", fmt.Sprintf(s, a...), cc))
		}
	}
}

func TestC_Collection(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		col     vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("unable to load: invalid nil IRI"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:    "invalid collection type",
			path:    "/inbox",
			col:     &vocab.Collection{ID: "http://example.com/~jdoe/inbox", Type: vocab.NoteType, TotalItems: 0, AttributedTo: vocab.IRI("http://example.com/~jdoe")},
			wantErr: errors.Errorf("response item type is not a valid collection: \"Note\""),
		},
		{
			name: "ordered collection",
			path: "/inbox",
			col:  &vocab.OrderedCollection{ID: "http://example.com/~jdoe/inbox", Type: vocab.OrderedCollectionType, TotalItems: 0, AttributedTo: vocab.IRI("http://example.com/~jdoe")},
			want: &vocab.OrderedCollection{ID: "http://example.com/~jdoe/inbox", Type: vocab.OrderedCollectionType, TotalItems: 0, AttributedTo: vocab.IRI("http://example.com/~jdoe")},
		},
		{
			name: "ordered collection page",
			path: "/inbox",
			col:  &vocab.OrderedCollectionPage{ID: "http://example.com/~jdoe/inbox?type=Create", Type: vocab.OrderedCollectionPageType, TotalItems: 1, AttributedTo: vocab.IRI("http://example.com/~jdoe"), OrderedItems: vocab.ItemCollection{vocab.IRI("http://example.com")}},
			want: &vocab.OrderedCollectionPage{ID: "http://example.com/~jdoe/inbox?type=Create", Type: vocab.OrderedCollectionPageType, TotalItems: 1, AttributedTo: vocab.IRI("http://example.com/~jdoe"), OrderedItems: vocab.ItemCollection{vocab.IRI("http://example.com")}},
		},
		{
			name: "collection",
			path: "/inbox",
			col:  &vocab.Collection{ID: "http://example.com/~jdoe/inbox", Type: vocab.CollectionType, TotalItems: 0, AttributedTo: vocab.IRI("http://example.com/~jdoe")},
			want: &vocab.Collection{ID: "http://example.com/~jdoe/inbox", Type: vocab.CollectionType, TotalItems: 0, AttributedTo: vocab.IRI("http://example.com/~jdoe")},
		},
		{
			name: "collection page",
			path: "/inbox",
			col:  &vocab.CollectionPage{ID: "http://example.com/~jdoe/inbox?type=Create", Type: vocab.CollectionPageType, TotalItems: 1, AttributedTo: vocab.IRI("http://example.com/~jdoe"), Items: vocab.ItemCollection{vocab.IRI("http://example.com")}},
			want: &vocab.CollectionPage{ID: "http://example.com/~jdoe/inbox?type=Create", Type: vocab.CollectionPageType, TotalItems: 1, AttributedTo: vocab.IRI("http://example.com/~jdoe"), Items: vocab.ItemCollection{vocab.IRI("http://example.com")}},
		},
		{
			name: "items",
			path: "/inbox",
			col:  vocab.ItemCollection{vocab.IRI("http://example.com"), &vocab.Object{ID: "http://example.com/1", Type: vocab.NoteType}},
			want: &vocab.ItemCollection{vocab.IRI("http://example.com"), &vocab.Object{ID: "http://example.com/1", Type: vocab.NoteType}},
		},
		{
			name: "iris",
			path: "/inbox",
			col:  vocab.IRIs{vocab.IRI("http://example.com"), vocab.IRI("http://example.com/1")},
			want: &vocab.ItemCollection{vocab.IRI("http://example.com"), vocab.IRI("http://example.com/1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/inbox" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.col)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Collection(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Collection() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Collection() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func areItems(a, b any) bool {
	_, ok1 := a.(vocab.Item)
	_, ok2 := b.(vocab.Item)
	return ok1 && ok2
}

func compareItems(x, y any) bool {
	var i1 vocab.Item
	var i2 vocab.Item
	if ic1, ok := x.(vocab.Item); ok {
		i1 = ic1
	}
	if ic2, ok := y.(vocab.Item); ok {
		i2 = ic2
	}
	return vocab.ItemsEqual(i1, i2) || vocab.ItemsEqual(i2, i1)
}

var EquateItems = cmp.FilterValues(areItems, cmp.Comparer(compareItems))

func TestC_Inbox(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Inbox),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/inbox" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Inbox(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Inbox() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Inbox() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func mockActor(id vocab.IRI, name string) *vocab.Actor {
	id = id.AddPath("~" + name)
	return &vocab.Actor{
		ID:                id,
		PreferredUsername: vocab.DefaultNaturalLanguage(name),
		Type:              vocab.PersonType,
		Outbox:            vocab.Outbox.IRI(id),
		Inbox:             vocab.Inbox.IRI(id),
		Followers:         vocab.Followers.IRI(id),
		Following:         vocab.Following.IRI(id),
		Shares:            vocab.Shares.IRI(id),
		Liked:             vocab.Liked.IRI(id),
		Likes:             vocab.Likes.IRI(id),
		Replies:           vocab.Replies.IRI(id),
	}
}

func mockCollection(name string, c vocab.CollectionPath) vocab.CollectionInterface {
	actor := vocab.IRI("http://example.com/").AddPath("~" + name)
	var items vocab.ItemCollection
	activities := vocab.ItemCollection{
		&vocab.Activity{
			ID:    "http://example.com/1",
			Type:  vocab.CreateType,
			Actor: actor,
			Object: &vocab.Object{
				ID:      "http://example.com/note-1",
				Type:    vocab.NoteType,
				Content: vocab.DefaultNaturalLanguage("Answer #1"),
			},
		},
		&vocab.Question{
			ID:      "http://example.com/2",
			Type:    vocab.QuestionType,
			Content: vocab.DefaultNaturalLanguage("question ?"),
			OneOf: vocab.ItemCollection{
				vocab.IRI("http://example.com/note-1"),
				&vocab.Object{
					Type:    vocab.NoteType,
					Content: vocab.DefaultNaturalLanguage("Answer #2"),
				},
			},
		},
	}
	actors := vocab.ItemCollection{
		&vocab.Actor{ID: "http://example.com/~alice"},
		&vocab.Actor{ID: "http://example.com/~jane"},
	}
	objects := vocab.ItemCollection{
		&vocab.Object{
			Type:    vocab.NoteType,
			Content: vocab.DefaultNaturalLanguage("Answer #2"),
		},
		&vocab.Object{
			ID:      "http://example.com/note-1",
			Type:    vocab.NoteType,
			Content: vocab.DefaultNaturalLanguage("Answer #1"),
		},
	}

	switch c {
	case vocab.Inbox, vocab.Outbox, vocab.Shares, vocab.Likes:
		items = activities
	case vocab.Followers, vocab.Following:
		items = actors
	case vocab.Liked, vocab.Replies:
		items = objects
	}
	return &vocab.OrderedCollection{
		ID:           c.IRI(actor),
		Type:         vocab.OrderedCollectionType,
		TotalItems:   uint(len(items)),
		AttributedTo: actor,
		OrderedItems: items,
	}
}

func TestC_Outbox(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Outbox),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/outbox" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Outbox(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Outbox() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Outbox() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Followers(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Followers),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/followers" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Followers(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Followers() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Followers() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Following(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Following),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/following" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Following(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Following() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Following() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Liked(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Liked),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/liked" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Liked(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Liked() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Liked() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Likes(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Likes),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/likes" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Likes(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Likes() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Likes() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Shares(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Shares),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/shares" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Shares(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Shares() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Shares() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Replies(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		actor   vocab.Item
		want    vocab.CollectionInterface
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("item is nil"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load"),
		},
		{
			name:  "ordered collection",
			path:  "/",
			actor: mockActor("http://example.com/", "jdoe"),
			want:  mockCollection("jdoe", vocab.Replies),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/replies" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.want)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Replies(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Replies() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Replies() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Actor(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		act     vocab.Actor
		want    *vocab.Actor
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("unable to load actor: invalid nil IRI"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load actor"),
		},
		{
			name: "jdoe",
			path: "/~jdoe",
			act:  *mockActor("http://example.com/", "jdoe"),
			want: mockActor("http://example.com/", "jdoe"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/~jdoe" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, err := vocab.MarshalJSON(tt.act)
				if err != nil {
					t.Errorf("Unable to marshal item: %s", err)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Actor(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Actor() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Actor() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}

func TestC_Object(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		act     vocab.Object
		want    *vocab.Object
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("unable to load object: invalid nil IRI"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load object"),
		},
		{
			name: "jdoe",
			path: "/~jdoe",
			act:  *mockObject(),
			want: mockObject(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/~jdoe" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, err := vocab.MarshalJSON(tt.act)
				if err != nil {
					t.Errorf("Unable to marshal item: %s", err)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Object(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Object() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Object() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}
func mockObject() *vocab.Object {
	id := vocab.IRI("http://example.com/").AddPath("1")
	return &vocab.Object{
		ID:      id,
		Type:    vocab.NoteType,
		Shares:  vocab.Shares.IRI(id),
		Likes:   vocab.Likes.IRI(id),
		Replies: vocab.Replies.IRI(id),
	}
}

func TestC_Activity(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		act     vocab.Activity
		want    *vocab.Activity
		wantErr error
	}{
		{
			name:    "empty",
			wantErr: errors.Newf("unable to load activity: invalid nil IRI"),
		},
		{
			name:    "not empty",
			path:    "/invalid",
			want:    nil,
			wantErr: errors.Annotatef(errf("unable to load from the ActivityPub end point"), "unable to load activity"),
		},
		{
			name: "jdoe",
			path: "/~jdoe",
			act:  *mockActivity(),
			want: mockActivity(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/~jdoe" {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, err := vocab.MarshalJSON(tt.act)
				if err != nil {
					t.Errorf("Unable to marshal item: %s", err)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.Activity(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Activity() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("Activity() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}
func FirstOr(it ...vocab.Item) vocab.Item {
	if len(it) == 0 {
		return nil
	}
	if len(it) == 1 {
		return vocab.ItemCollection(it).First()
	}
	return vocab.ItemCollection(it)
}

func mockActivity(a ...vocab.Item) *vocab.Activity {
	id := vocab.IRI("http://example.com/").AddPath("666")
	act := &vocab.Activity{
		ID:   id,
		Type: vocab.FollowType,
	}
	act.Actor = FirstOr(a...)
	return act
}

func TestC_ToOutbox(t *testing.T) {
	tests := []struct {
		name    string
		toSend  vocab.Item
		wantIRI vocab.IRI
		wantIt  vocab.Item
		wantErr error
	}{
		{
			name: "empty",
		},
		{
			name:    "invalid activity type",
			toSend:  &vocab.Actor{},
			wantErr: errors.Annotatef(errors.Newf("unable to convert %T to %T", new(vocab.Actor), new(vocab.IntransitiveActivity)), "object of type %T is not an activity", new(vocab.Actor)),
		},
		{
			name:    "withValidActivity",
			toSend:  mockActivity(),
			wantIRI: "",
			wantIt:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}
			ctx := context.Background()

			name := "jdoe"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != filepath.Join("/~"+name, "outbox") {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				w.WriteHeader(http.StatusOK)
				raw, _ := vocab.MarshalJSON(tt.wantIt)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			_ = vocab.OnIntransitiveActivity(tt.toSend, func(act *vocab.IntransitiveActivity) error {
				act.Actor = mockActor(vocab.IRI(srv.URL), name)
				return nil
			})

			gotIRI, gotIt, err := c.ToOutbox(ctx, tt.toSend)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Outbox() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if gotIRI != tt.wantIRI {
				t.Errorf("ToOutbox() got IRI = %s", cmp.Diff(tt.wantIRI, gotIRI, EquateItems))
			}
			if !cmp.Equal(gotIt, tt.wantIt, EquateItems) {
				t.Errorf("ToOutbox() got item = %s", cmp.Diff(tt.wantIt, gotIt, EquateItems))
			}
		})
	}
}

func TestC_ToInbox(t *testing.T) {
	tests := []struct {
		name    string
		toSend  vocab.Item
		wantIRI vocab.IRI
		wantIt  vocab.Item
		wantErr error
	}{
		{
			name: "empty",
		},
		{
			name:    "invalid activity type",
			toSend:  &vocab.Actor{},
			wantErr: errors.Annotatef(errors.Newf("unable to convert %T to %T", new(vocab.Actor), new(vocab.IntransitiveActivity)), "object of type %T is not an activity", new(vocab.Actor)),
		},
		{
			name:    "withValidActivity",
			toSend:  mockActivity(),
			wantIRI: "",
			wantIt:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c: defaultClient,
				l: lw.Dev(lw.SetOutput(t.Output())),
			}
			ctx := context.Background()

			name := "jdoe"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != filepath.Join("/~"+name, "inbox") {
					errors.NotFound.ServeHTTP(w, r)
					return
				}
				raw, _ := vocab.MarshalJSON(tt.wantIt)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			_ = vocab.OnIntransitiveActivity(tt.toSend, func(act *vocab.IntransitiveActivity) error {
				act.Actor = mockActor(vocab.IRI(srv.URL), name)
				return nil
			})

			gotIRI, gotIt, err := c.ToInbox(ctx, tt.toSend)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("Inbox() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if gotIRI != tt.wantIRI {
				t.Errorf("ToInbox() got IRI = %s", cmp.Diff(tt.wantIRI, gotIRI, EquateItems))
			}
			if !cmp.Equal(gotIt, tt.wantIt, EquateItems) {
				t.Errorf("ToInbox() got item = %s", cmp.Diff(tt.wantIt, gotIt, EquateItems))
			}
		})
	}
}

func TestActivityActorTargetCollections(t *testing.T) {
	type args struct {
		act   vocab.Item
		colFn iriGenFn
	}
	tests := []struct {
		name    string
		args    args
		want    vocab.IRIs
		wantErr error
	}{
		{
			name:    "empty",
			args:    args{},
			wantErr: errors.Newf("invalid collection IRI function"),
		},
		{
			name: "w/ activity, w/o colFn",
			args: args{
				act:   mockActivity(mockActor("http:/example.com", "jdoe")),
				colFn: nil,
			},
			want:    nil,
			wantErr: errors.Newf("invalid collection IRI function"),
		},
		{
			name: "w/o activity, w/ colFn",
			args: args{colFn: inbox},
			want: nil,
		},
		{
			name: "inbox single actor",
			args: args{
				act:   mockActivity(mockActor("http://example.com", "jdoe")),
				colFn: inbox,
			},
			want: vocab.IRIs{"http://example.com/~jdoe/inbox"},
		},
		{
			name: "inbox multiple actors",
			args: args{
				act:   mockActivity(mockActor("http://example.com", "jdoe"), mockActor("http://example.com", "alice")),
				colFn: inbox,
			},
			want: vocab.IRIs{"http://example.com/~jdoe/inbox", "http://example.com/~alice/inbox"},
		},
		{
			name: "outbox single actor",
			args: args{
				act:   mockActivity(mockActor("http://example.com", "jdoe")),
				colFn: outbox,
			},
			want: vocab.IRIs{"http://example.com/~jdoe/outbox"},
		},
		{
			name: "outbox multiple actors",
			args: args{
				act:   mockActivity(mockActor("http://example.com", "jdoe"), mockActor("http://example.com", "alice")),
				colFn: outbox,
			},
			want: vocab.IRIs{"http://example.com/~jdoe/outbox", "http://example.com/~alice/outbox"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ActivityActorTargetCollections(tt.args.act, tt.args.colFn)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("ActivityActorTargetCollections() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("ActivityActorTargetCollections() got = %s", cmp.Diff(tt.want, got, EquateItems))
			}
		})
	}
}
