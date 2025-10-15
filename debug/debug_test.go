package debug

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ap/errors"
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

func Test_Transport_RoundTrip(t *testing.T) {
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

			dt := Transport{Base: http.DefaultTransport, where: where}
			req := httptest.NewRequest(http.MethodPost, server.URL, bytes.NewBuffer(tt.body))
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
				t.Errorf("RoundTrip() got reponse bytes = %s, wanted %s", gotBody, tt.resp)
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
				loggedReq := loggedBuff[bytes.Index(loggedBuff, []byte{'\n', '\n'})+3 : boundaryIndex]
				loggedRes := loggedBuff[bytes.LastIndex(loggedBuff, []byte{'\n', '\n'})+2:]
				if !bytes.Equal(loggedReq, tt.body) {
					t.Errorf("RoundTrip() log request don't match: %v vs %v", loggedReq, tt.body)
				}
				if !bytes.Equal(loggedRes, tt.resp) {
					t.Errorf("RoundTrip() log response don't match: %v vs %v", loggedReq, tt.resp)
				}
				return nil
			})
			if err != nil {
				t.Errorf("RoundTrip() unable to find logged request: %v", err)
			}
		})
	}
}
