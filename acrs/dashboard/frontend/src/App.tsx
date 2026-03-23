import { FormEvent, useMemo, useState } from "react";

type Finding = {
  title: string;
  vulnerability_type: string;
  severity: string;
  location: string;
  evidence: string;
  confidence: number;
};

type Artifact = {
  module: string;
  summary: string;
  data: Record<string, unknown>;
};

type ExperimentResult = {
  experiment_id: string;
  artifacts: Artifact[];
  report: {
    software: string;
    risk_summary: string;
    mitigation_strategies: string[];
    detected_languages: Record<string, number>;
    scanned_files: number;
    website_profile: Record<string, unknown>;
    json_report_path: string | null;
    markdown_report_path: string | null;
  };
  findings: Finding[];
};

type RemediationFile = {
  file_path: string;
  language: string;
  changes_applied: string[];
  backup_path: string | null;
};

type RemediationResult = {
  status: string;
  message: string;
  scanned_files: number;
  detected_languages: Record<string, number>;
  modified_files: RemediationFile[];
};

const API_BASE = "http://127.0.0.1:8000";

function fixGuidanceForType(vulnType: string): string {
  const map: Record<string, string> = {
    "security-header": "Add strict security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) at the gateway/web server layer.",
    "transport-security": "Enforce HTTPS-only serving, redirect all HTTP to HTTPS, and deploy HSTS with a strong max-age.",
    "credential-exposure": "Never accept login forms over HTTP. Restrict auth endpoints to HTTPS and secure cookies.",
    "reflected-input": "Apply context-aware output encoding and strict input validation for reflected parameters.",
    "unsafe-code-execution": "Remove dynamic execution primitives (`eval`/`exec`) and replace with strict parsers/allowlists.",
    "input-validation": "Validate and canonicalize untrusted inputs with explicit schemas and reject malformed payloads.",
  };
  return map[vulnType] || "Apply secure coding controls, add regression tests, and verify with targeted re-scan.";
}

export function App() {
  const [softwarePath, setSoftwarePath] = useState("");
  const [language, setLanguage] = useState("auto");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [sharpWebsiteDetection, setSharpWebsiteDetection] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExperimentResult | null>(null);
  const [remediation, setRemediation] = useState<RemediationResult | null>(null);
  const [grantPermission, setGrantPermission] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const severitySummary = useMemo(() => {
    if (!result) {
      return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    }
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of result.findings) {
      const key = finding.severity.toLowerCase() as keyof typeof counts;
      if (key in counts) {
        counts[key] += 1;
      }
    }
    return counts;
  }, [result]);

  const webArtifact = useMemo(() => {
    if (!result) {
      return null;
    }
    if (result.report.website_profile && Object.keys(result.report.website_profile).length > 0) {
      return { summary: "Live website scan profile", data: result.report.website_profile };
    }
    return result.artifacts.find((a) => a.module === "web_sharp_detection") ?? null;
  }, [result]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setRemediation(null);

    try {
      const response = await fetch(`${API_BASE}/experiments/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          software_path: softwarePath || "",
          language,
          website_url: websiteUrl || null,
          sharp_website_detection: sharpWebsiteDetection,
          web_max_pages: 50,
          web_max_depth: 2,
          max_fuzz_iterations: 40,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const data = (await response.json()) as ExperimentResult;
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function runRemediation() {
    if (!result) {
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const roots = Array.from(new Set([softwarePath, result.report.software].filter(Boolean)));
      const response = await fetch(`${API_BASE}/experiments/${result.experiment_id}/remediate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_file_access: grantPermission,
          allow_write: grantPermission,
          allowed_root_paths: roots,
          dry_run: false,
        }),
      });
      if (!response.ok) {
        throw new Error(await response.text());
      }
      const data = (await response.json()) as RemediationResult;
      setRemediation(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="container">
      <h1>SNSX CRS Security Research Interface</h1>
      <p>Authorized target scanning with technical reporting and remediation workflow.</p>

      <form onSubmit={onSubmit} className="panel">
        <label>
          Local File or Folder Path (optional for website-only scan)
          <input
            value={softwarePath}
            onChange={(e) => setSoftwarePath(e.target.value)}
            placeholder="/absolute/path/to/source"
          />
        </label>

        <label>
          Language Profile Hint
          <input value={language} onChange={(e) => setLanguage(e.target.value)} placeholder="auto" />
        </label>

        <label>
          Website URL (optional)
          <input
            value={websiteUrl}
            onChange={(e) => setWebsiteUrl(e.target.value)}
            placeholder="https://authorized-target.example"
          />
        </label>

        <label>
          <input
            type="checkbox"
            checked={sharpWebsiteDetection}
            onChange={(e) => setSharpWebsiteDetection(e.target.checked)}
          />
          Enable deep website security analysis mode
        </label>

        <button disabled={loading}>{loading ? "Running experiment..." : "Run Experiment"}</button>
      </form>

      {error ? <pre className="error">{error}</pre> : null}

      {result ? (
        <article className="panel reportDoc">
          <header>
            <h2>Security Assessment Report</h2>
            <p><strong>Experiment ID:</strong> {result.experiment_id}</p>
            <p><strong>Target:</strong> {result.report.software}</p>
            <p><strong>Summary:</strong> {result.report.risk_summary}</p>
          </header>

          <section className="summaryGrid">
            <div className="statCard"><span>Critical</span><strong>{severitySummary.critical}</strong></div>
            <div className="statCard"><span>High</span><strong>{severitySummary.high}</strong></div>
            <div className="statCard"><span>Medium</span><strong>{severitySummary.medium}</strong></div>
            <div className="statCard"><span>Low</span><strong>{severitySummary.low}</strong></div>
            <div className="statCard"><span>Info</span><strong>{severitySummary.info}</strong></div>
            <div className="statCard"><span>Findings</span><strong>{result.findings.length}</strong></div>
          </section>

          <section>
            <h3>Technology and Codebase Profile</h3>
            <p><strong>Scanned Files:</strong> {result.report.scanned_files}</p>
            <pre>{JSON.stringify(result.report.detected_languages, null, 2)}</pre>
            <p><strong>JSON Report:</strong> {result.report.json_report_path || "N/A"}</p>
            <p><strong>Markdown Report:</strong> {result.report.markdown_report_path || "N/A"}</p>
          </section>

          {webArtifact ? (
            <section>
              <h3>Website Deep Inspection Details</h3>
              <p>{webArtifact.summary}</p>
              <pre>{JSON.stringify(webArtifact.data, null, 2)}</pre>
            </section>
          ) : websiteUrl ? (
            <section>
              <h3>Website Deep Inspection Details</h3>
              <p>No live website profile was generated for this run. Check URL reachability and rerun.</p>
            </section>
          ) : null}

          <section>
            <h3>Detailed Findings (Pin-to-Pin)</h3>
            {result.findings.length === 0 ? (
              <p>No findings identified in this run.</p>
            ) : (
              <div className="findingList">
                {result.findings.map((finding, i) => (
                  <article key={`${finding.title}-${i}`} className="findingCard">
                    <h4>
                      [{finding.severity.toUpperCase()}] {finding.title}
                    </h4>
                    <p><strong>Type:</strong> {finding.vulnerability_type}</p>
                    <p><strong>Location:</strong> {finding.location}</p>
                    <p><strong>Confidence:</strong> {finding.confidence}</p>
                    <p><strong>Technical Evidence:</strong> {finding.evidence}</p>
                    <p><strong>Fix Guidance:</strong> {fixGuidanceForType(finding.vulnerability_type)}</p>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section>
            <h3>Global Mitigation Plan</h3>
            <ul>
              {result.report.mitigation_strategies.map((m, i) => (
                <li key={`mit-${i}`}>{m}</li>
              ))}
            </ul>
          </section>

          <section>
            <h3>Auto Remediation Approval</h3>
            <label>
              <input
                type="checkbox"
                checked={grantPermission}
                onChange={(e) => setGrantPermission(e.target.checked)}
              />
              I authorize file/folder access and write changes for this target.
            </label>
            <button type="button" disabled={loading} onClick={runRemediation}>
              {loading ? "Applying remediation..." : "Run Auto Remediation"}
            </button>
          </section>

          {remediation ? (
            <section>
              <h3>Remediation Execution Output</h3>
              <p><strong>Status:</strong> {remediation.status}</p>
              <p>{remediation.message}</p>
              <p><strong>Scanned Files:</strong> {remediation.scanned_files}</p>
              <pre>{JSON.stringify(remediation.detected_languages, null, 2)}</pre>
              <pre>{JSON.stringify(remediation.modified_files, null, 2)}</pre>
            </section>
          ) : null}
        </article>
      ) : null}
    </main>
  );
}
