// Example Cedar policy set for ToolConnect.
//
// The entity attributes available to policies (see toolconnect/policy.py):
//   principal (Agent):  privacy_tier, kind, delegated
//   resource  (Tool):   effect, reversible, idempotent, requires_approval,
//                       reads_sensitive, external_sink
//
// Everything not explicitly permitted is denied (Cedar default-deny), and an
// unasserted tool never reaches policy evaluation at all.

// Local agents may invoke read-effect tools that do not read sensitive data.
@id("local-reads")
permit(
    principal,
    action == Action::"invoke",
    resource
) when {
    principal.privacy_tier == "local" &&
    resource.effect == "read" &&
    !resource.reads_sensitive
};

// Nothing running at the rented privacy tier may touch a sensitive reader.
// Delegation cannot launder this: effective_tier() is the worst tier in the chain.
@id("no-sensitive-reads-for-rented")
forbid(
    principal,
    action == Action::"invoke",
    resource
) when {
    principal.privacy_tier == "rented" &&
    resource.reads_sensitive
};
