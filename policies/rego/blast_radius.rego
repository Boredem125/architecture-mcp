package sandbox.blast_radius

default deny := false

deny {
    input.session.max_writes > 0
    input.action_type == "WRITE"
    input.session.write_count >= input.session.max_writes
}

deny {
    input.session.total_requests >= input.session.max_requests
}
