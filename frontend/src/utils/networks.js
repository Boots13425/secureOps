// Display helpers for the detected-VLAN card. Kept out of the Dashboard so the
// Dashboard card and the Discovery Networks section describe a network the same
// way, rather than each re-deriving the label and badge.

const SEEN_KEY = 'secureops.seen-network-ids'

// "New" is tracked in the browser because the backend has no notification
// stream for it yet: a network counts as new until this browser has listed it
// once. That is honest about what it knows - it says "new to you", not "new on
// the network" - and it needs no polling of a table that is only written by an
// explicit detection run.
export function markNetworksSeen(networks) {
  try {
    const previous = readSeen()
    const ids = networks.map((network) => network.network_id).filter(Boolean)
    localStorage.setItem(SEEN_KEY, JSON.stringify([...new Set([...previous, ...ids])]))
  } catch {
    // Private browsing / disabled storage: the badge simply stops working.
  }
}

function readSeen() {
  try {
    const raw = JSON.parse(localStorage.getItem(SEEN_KEY) || '[]')
    return Array.isArray(raw) ? raw : []
  } catch {
    return []
  }
}

export function newNetworkIds(networks) {
  const seen = readSeen()
  return new Set(networks.filter((n) => n.network_id && !seen.includes(n.network_id)).map((n) => n.network_id))
}

export function networkLabel(network) {
  const vlan = network.vlan_id ? `VLAN ${network.vlan_id}` : null
  const cidr = network.cidr_text || network.cidr || null
  if (vlan && cidr) return `${vlan} · ${cidr}`
  return vlan || cidr || network.label || 'Unnamed network'
}

// "Not reachable" wins over the scan state: a VLAN that cannot be routed to was
// never scannable, so reporting it as merely "not scanned" would imply it is
// still worth scanning. The reverse is also deliberate - a network that has
// been scanned stays "Scanned" even if detection later marks it unreachable,
// because the scan really did happen.
export function networkStatus(network) {
  if (!network.is_scannable) return { label: 'Not reachable', tone: 'danger' }
  if (network.status === 'scanned') return { label: 'Scanned', tone: 'ok' }
  return { label: 'Not scanned', tone: 'neutral' }
}

// Why the system believes this network exists and is reachable, in one line.
// "direct" means it is attached to a queried router/switch; "routed" means it
// was found in a routing table and the chain that gets there is listed, so the
// claim can be checked rather than taken on trust.
export function reachabilitySummary(network) {
  const hops = network.reachability_hops || []
  if (network.reachability_path === 'routed' && hops.length) {
    const chain = hops.map((hop) => hop.router_ip).join(' → ')
    return `Reachable via routing table · ${hops.length} hop${hops.length === 1 ? '' : 's'} from ${chain}`
  }
  if (network.reachability_path === 'direct') {
    return 'Directly connected to the reporting router/switch'
  }
  return null
}
