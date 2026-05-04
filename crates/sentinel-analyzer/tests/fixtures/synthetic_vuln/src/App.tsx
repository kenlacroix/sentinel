// Synthetic-vuln fixture: intentional webview-side issues.
//
// Issues seeded here, with expected rule_id:
//
//   - eval() in webview                            webview.eval
//   - dangerouslySetInnerHTML on user-controlled HTML   webview.dangerously_set_inner_html
//
// Adding or removing issues REQUIRES updating tests/end_to_end.rs.

export default function App({ ipc }) {
    const result = eval(ipc.expression);
    return <div dangerouslySetInnerHTML={{ __html: ipc.html }} />;
}
