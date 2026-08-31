package sandbox.temporal_scope

default allow := false

allow {
    time.now_ns() < input.session.expires_at_ns
}
