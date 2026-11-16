package shield

import "net/http"

type credentialProxy struct{}

func (credentialProxy) connect(*Proxy, http.ResponseWriter, *http.Request, EgressRecord, string) bool {
	return false
}

func (credentialProxy) plain(http.ResponseWriter, *http.Request, string) bool { return false }

func (credentialProxy) self(*Proxy, http.ResponseWriter, *http.Request) bool { return false }
