import type { AnalysisResult, ExplanationBundle, Finding } from "./contracts";

export async function explanationMatches(
  bundle: Pick<
    ExplanationBundle,
    | "analysis_id"
    | "configuration_id"
    | "device_id"
    | "source_sha256"
    | "finding_id"
    | "finding_sha256"
    | "explanation"
    | "documents"
  >,
  analysis: Pick<
    AnalysisResult,
    | "analysis_id"
    | "configuration_id"
    | "device_id"
    | "source_sha256"
    | "explanations"
  >,
  finding: Pick<Finding, "finding_id">,
): Promise<boolean> {
  const saved = analysis.explanations.find(
    (item) => item.finding_id === finding.finding_id,
  );
  if (
    !saved ||
    bundle.analysis_id !== analysis.analysis_id ||
    bundle.configuration_id !== analysis.configuration_id ||
    bundle.device_id !== analysis.device_id ||
    bundle.source_sha256 !== analysis.source_sha256 ||
    bundle.finding_id !== finding.finding_id ||
    bundle.finding_sha256 !== saved.finding_sha256 ||
    JSON.stringify(bundle.explanation) !== JSON.stringify(saved)
  )
    return false;
  // Hashes detect inconsistent transport contents, not forged publisher identity.
  for (const chunk of bundle.documents) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(chunk.content),
    );
    const actual = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    if (actual !== chunk.content_sha256) return false;
  }
  return true;
}
