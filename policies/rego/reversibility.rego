package sandbox.reversibility

default escalate := false

escalate {
    input.parameters.irreversible == true
    input.risk_tier != "CRITICAL"
}

escalate {
    input.action_type == "EXECUTE"
    contains(input.parameters.command, "rm ")
    contains(input.parameters.command, "-rf")
}

escalate {
    input.action_type == "NETWORK"
    input.parameters.method != "GET"
}
