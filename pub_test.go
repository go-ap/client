package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestC_collection(t *testing.T) {
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
			want: &vocab.IRIs{vocab.IRI("http://example.com"), vocab.IRI("http://example.com/1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := C{
				c:      defaultClient,
				l:      lw.Dev(lw.SetOutput(t.Output())),
				infoFn: ctxLogFn(t),
				errFn:  ctxLogFn(t),
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

			ctx := context.Background()
			var iri vocab.IRI
			if tt.path != "" {
				iri = vocab.IRI(srv.URL).AddPath(tt.path)
			}

			got, err := c.collection(ctx, iri)
			if !cmp.Equal(err, tt.wantErr, EquateWeakErrors) {
				t.Errorf("collection() error = %s", cmp.Diff(tt.wantErr, err, EquateWeakErrors))
				return
			}
			if !cmp.Equal(got, tt.want, EquateItems) {
				t.Errorf("collection() got = %s", cmp.Diff(tt.want, got, EquateItems))
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
