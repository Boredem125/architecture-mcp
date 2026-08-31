package sandbox.action_scope

default allow := false

allow {
    input.action_type == "READ"
    startswith(input.parameters.path, input.session.workspace_root)
}

allow {
    input.action_type == "WRITE"
    startswith(input.parameters.path, input.session.workspace_root)
}

allow {
    input.action_type == "NETWORK"
    input.parameters.host == input.session.allowed_network_hosts[_]
}
