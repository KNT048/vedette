1. [→ Kiên/response] L7 is not closed by this port: Telegram button decisions (`modules/response/chat.go` chatGate ~88-123) and email link/reply-code use (`modules/response/links.go:462` approverValid) never call Linked. Add the same port to response.Config (one adapter in cmd/vedette serves both) and check there; an error fails closed.
2. D-191 and the story criterion must land (Mac).
