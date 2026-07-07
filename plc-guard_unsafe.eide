#! VULNERABLE plc-guard — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant setParam confidence 75

let raw = fetch<web>
privileged { setParam(raw) }  # tainted -> tool: REJECTED
