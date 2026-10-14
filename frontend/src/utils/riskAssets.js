// GET /risk/assets returns a grouped object, not a flat list:
//   { last_ranked_at, ranking_stale, ranked: [...], not_in_document: [...], missing_from_scan: [...] }
//
// Every consumer has to unwrap those groups before using array methods. Doing
// that inline is what broke AssetDetail ("find is not a function") and
// SecurityPosture ("slice is not a function") when the endpoint was reshaped:
// `(data || [])` is no defence, because the response is a truthy object.
//
// These accessors are the single place that knows the shape, and they degrade
// to [] instead of throwing if the endpoint changes again.

// missing_from_scan rows are unmatched *document* rows (no asset_id — they are
// keyed by IP), so they are deliberately excluded from asset lookups.
export function rankedAssets(data) {
  return Array.isArray(data?.ranked) ? data.ranked : []
}

export function notInDocumentAssets(data) {
  return Array.isArray(data?.not_in_document) ? data.not_in_document : []
}

export function missingFromScanAssets(data) {
  return Array.isArray(data?.missing_from_scan) ? data.missing_from_scan : []
}

export function findRiskAsset(data, assetId) {
  if (!assetId) return null
  return [...rankedAssets(data), ...notInDocumentAssets(data)].find((r) => r.asset_id === assetId) || null
}
