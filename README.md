# About GoActivityPub: Client

[![MIT Licensed](https://img.shields.io/github/license/go-ap/client.svg)](https://raw.githubusercontent.com/go-ap/client/master/LICENSE)
[![Build Status](https://builds.sr.ht/~mariusor/client.svg)](https://builds.sr.ht/~mariusor/client)
[![Test Coverage](https://img.shields.io/codecov/c/github/go-ap/client.svg)](https://codecov.io/gh/go-ap/client)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-ap/client)](https://goreportcard.com/report/github.com/go-ap/client)

This project is part of the [GoActivityPub](https://github.com/go-ap) library which helps with creating ActivityPub applications using the Go programming language.

It can be used to create an API client for ActivityPub servers.

It supports retrieval of ActivityPub objects and collections, but also submitting Activities to servers, either as a [C2S](https://www.w3.org/TR/activitypub/#client-to-server-interactions) or as a [S2S](https://www.w3.org/TR/activitypub/#server-to-server-interactions) client.

It can supports plugging in custom authorization logic. We usually authorize the requests with either HTTP Singatures (for server to server interactions) or OAuth2 (for client to server interactions).

You can find an expanded documentation about the whole library [on SourceHut](https://man.sr.ht/~mariusor/go-activitypub/go-ap/index.md).

For discussions about the projects you can write to the discussions mailing list: [~mariusor/go-activitypub-discuss@lists.sr.ht](mailto:~mariusor/go-activitypub-discuss@lists.sr.ht)

For patches and bug reports please use the dev mailing list: [~mariusor/go-activitypub-dev@lists.sr.ht](mailto:~mariusor/go-activitypub-dev@lists.sr.ht)
