package sandbox.session_scope

default allow := false

allow {
    input.intent_class == input.session.allowed_actions[_]
}
