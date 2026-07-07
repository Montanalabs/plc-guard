#! Industrial PLC guard — untrusted a setpoint can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires setParam — the industrial plc guard sink
#! @effect io
#! @confidence 75
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant setParam confidence 75

type Param = Speed | Torque | TempSet
type Decision = SetParam(Param) | RejectParam

let raw = fetch<web>  # UNTRUSTED a setpoint — tainted
quarantined { let d = extract<Decision>(raw) confidence 75 }  # only a fixed Decision (payloads too) crosses
privileged { setParam(d) }  # act on the trusted decision only
