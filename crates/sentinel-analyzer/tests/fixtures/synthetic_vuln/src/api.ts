// Synthetic-vuln fixture: intentional network issue.
//
// Issues seeded here, with expected rule_id:
//
//   - plain HTTP fetch                              network.http_in_fetch

export async function loadConfig() {
    return fetch("http://config.internal/load").then((r) => r.json());
}
