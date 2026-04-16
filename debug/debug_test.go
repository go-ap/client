package debug

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-ap/errors"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
)

const StatusFailedTest = http.StatusExpectationFailed

func sameBodyHandler(t *testing.T, bodyBuff, respBuff []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("RoundTrip() handler body read unexpected error = %v", err)
			w.WriteHeader(StatusFailedTest)
			return
		}
		//wantedBuff = append(wantedBuff, 'a', 'b')
		if !bytes.Equal(body, bodyBuff) {
			t.Errorf("RoundTrip() handler request body = %s, different than wanted %s", body, bodyBuff)
			w.WriteHeader(StatusFailedTest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBuff)
	}
}

func TestTransport_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		resp       []byte
		wantStatus int
		wantErr    error
	}{
		{
			name:       "empty",
			wantStatus: http.StatusOK,
		},
		{
			name:       "test",
			body:       []byte("test"),
			resp:       []byte("test123"),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			where := t.TempDir()
			server := httptest.NewServer(sameBodyHandler(t, tt.body, tt.resp))
			defer server.Close()

			dt := Transport{Base: http.DefaultTransport, where: where}
			var req *http.Request
			if tt.body != nil {
				req = httptest.NewRequest(http.MethodPost, server.URL, bytes.NewBuffer(tt.body))
			} else {
				req = httptest.NewRequest(http.MethodPost, server.URL, nil)
			}
			req.Header.Set("Date", time.Now().Format(http.TimeFormat))

			got, err := dt.RoundTrip(req)
			if (err != nil) && !errors.Is(tt.wantErr, err) {
				t.Errorf("RoundTrip() error = %v, wanted error %v", err, tt.wantErr)
				return
			}

			if tt.wantStatus != got.StatusCode {
				t.Errorf("RoundTrip() invalid status received = %s, wanted %d %s", got.Status, tt.wantStatus, http.StatusText(tt.wantStatus))
				return
			}

			gotBody, err := io.ReadAll(got.Body)
			if err != nil {
				t.Errorf("RoundTrip() unable to read response body: %v", err)
			}

			if err = got.Body.Close(); err != nil {
				t.Errorf("RoundTrip() unable to read response body: %v", err)
			}

			if !bytes.Equal(gotBody, tt.resp) {
				t.Errorf("RoundTrip() got response bytes = %s, wanted %s", gotBody, tt.resp)
			}

			err = filepath.WalkDir(where, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				ext := filepath.Ext(path)
				if ext != ".req" {
					return nil
				}
				loggedBuff, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("RoundTrip() unable to read logged request file: %v", err)
					return nil
				}
				boundaryIndex := bytes.Index(loggedBuff, []byte(boundary))
				if boundaryIndex < 0 {
					t.Errorf("RoundTrip() unable to read both request and response from log: %s", loggedBuff)
					return nil
				}
				loggedReqBody := loggedBuff[bytes.Index(loggedBuff, []byte("\r\n\r\n"))+4 : boundaryIndex]
				loggedResBody := loggedBuff[bytes.LastIndex(loggedBuff, []byte("\r\n\r\n"))+4:]
				if !bytes.Equal(loggedReqBody, tt.body) {
					t.Errorf("RoundTrip() logged request body don't match: %s vs %s", loggedReqBody, tt.body)
				}
				if !bytes.Equal(loggedResBody, tt.resp) {
					t.Errorf("RoundTrip() logged response body don't match: %s vs %s", loggedReqBody, tt.resp)
				}
				return nil
			})
			if err != nil {
				t.Errorf("RoundTrip() unable to find logged request: %v", err)
			}
		})
	}
}

func TestWithTransport(t *testing.T) {
	tests := []struct {
		name    string
		tr      http.RoundTripper
		want    *Transport
		wantErr error
	}{
		{
			name: "empty",
			want: &Transport{},
		},
		{
			name: "http.DefaultTransport",
			tr:   http.DefaultTransport,
			want: &Transport{Base: http.DefaultTransport},
		},
		{
			name: "oauth2.Transport",
			tr:   &oauth2.Transport{},
			want: &Transport{Base: &oauth2.Transport{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optFn := WithTransport(tt.tr)

			tr := Transport{}
			err := optFn(&tr)
			if !cmp.Equal(err, tt.wantErr) {
				t.Errorf("WithTransport() error %s", cmp.Diff(tt.wantErr, err))
			}

			if !cmp.Equal(tt.want, &tr, transportEquals) {
				t.Errorf("WithTransport() transport %s", cmp.Diff(tt.want, &tr, transportEquals))
			}
		})
	}
}

func areHttpTransports(t1, t2 any) bool {
	_, o1 := t1.(*http.Transport)
	_, o11 := t1.(http.Transport)
	_, o2 := t2.(*http.Transport)
	_, o21 := t2.(http.Transport)
	return o1 && o2 || o11 && o21
}

func compareHttpTransports(t1, t2 *http.Transport) bool {
	return (t1 != nil && t2 != nil) && reflect.DeepEqual(t1, t2)
}

func areTransports(t1, t2 any) bool {
	_, o1 := t1.(*Transport)
	_, o11 := t1.(Transport)
	_, o2 := t2.(*Transport)
	_, o21 := t2.(Transport)
	return o1 && o2 || o11 && o21
}

func compareTransports(t1, t2 *Transport) bool {
	return (t1 != nil && t2 != nil) && (reflect.DeepEqual(t1.Base, t2.Base) && t1.where == t2.where)
}

var transportEquals = cmp.FilterValues(areTransports, cmp.Comparer(compareTransports))
var httpTransportEquals = cmp.FilterValues(areHttpTransports, cmp.Comparer(compareHttpTransports))

func TestWithPath(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    *Transport
		wantErr error
	}{
		{
			name: "empty",
			want: &Transport{},
		},
		{
			name: "test",
			arg:  "test",
			want: &Transport{where: "test"},
		},
		{
			name: "empty string",
			arg:  "",
			want: &Transport{where: ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optFn := WithPath(tt.arg)

			tr := Transport{}
			err := optFn(&tr)
			if !cmp.Equal(err, tt.wantErr) {
				t.Errorf("WithPath() error %s", cmp.Diff(tt.wantErr, err))
			}

			if !cmp.Equal(tt.want, &tr, transportEquals) {
				t.Errorf("WithPath() transport %s", cmp.Diff(tt.want, &tr, transportEquals))
			}
		})
	}
}

func TestNew(t *testing.T) {
	tf, err := os.CreateTemp(t.TempDir(), "empty")
	if err != nil {
		t.Fatalf("Unable to create mock temp file: %s", err)
	}

	tempDir := t.TempDir()
	tests := []struct {
		name string
		args []OptionFn
		want http.RoundTripper
	}{
		{
			name: "empty",
			want: http.DefaultTransport,
		},
		{
			name: "with invalid directory",
			args: []OptionFn{WithPath(tf.Name())},
			want: http.DefaultTransport,
		},
		{
			name: "with valid temp dir",
			args: []OptionFn{WithPath(tempDir)},
			want: &Transport{where: tempDir, Base: http.DefaultTransport},
		},
		{
			name: "with valid temp dir and base transport",
			args: []OptionFn{WithPath(tempDir), WithTransport(&oauth2.Transport{})},
			want: &Transport{where: tempDir, Base: &oauth2.Transport{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args...); !cmp.Equal(got, tt.want, transportEquals, httpTransportEquals) {
				t.Errorf("New() = %s", cmp.Diff(tt.want, got, transportEquals, httpTransportEquals))
			}
		})
	}
}

func mockRequest(met, url string, body io.Reader) *http.Request {
	r, _ := http.NewRequest(met, url, body)
	return r
}

func areErrors(a, b any) bool {
	_, ok1 := a.(error)
	_, ok2 := b.(error)
	return ok1 && ok2
}

func compareErrors(x, y interface{}) bool {
	xe := x.(error)
	ye := y.(error)
	if errors.Is(xe, ye) || errors.Is(ye, xe) {
		return true
	}
	return xe.Error() == ye.Error()
}

var EquateWeakErrors = cmp.FilterValues(areErrors, cmp.Comparer(compareErrors))
