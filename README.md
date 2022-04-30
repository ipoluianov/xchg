# xchg
Traffic exchange service

A service allows you to do long-polling communication.

Features:
- simple service
- works as system service
- multiplatform (Linux/Widnows/MacOS)

API:

Get message (Long Polling):
"http://example.com:8987/r/{id}"

Send message:
"http://example.com:8987/w/{id}?d=some-data"
