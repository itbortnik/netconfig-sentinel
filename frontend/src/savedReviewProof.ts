import { stableJson } from "./contracts";

async function textDigest(value: string) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
export async function savedReviewProofMatches<
  T extends {
    review_json: string;
    review_sha256: string;
    outcome: { intent_sha256: string } | null;
  },
>(row: T) {
  const { review_json, review_sha256, ...body } = row;
  try {
    const objects: (Set<string> | null)[] = [];
    const tokens = [
      ...review_json.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,]+/gu),
    ];
    let intentStart = -1,
      rawIntent: string | undefined;
    for (let i = 0; i < tokens.length; i++) {
      const match = tokens[i]!,
        token = match[0];
      if (token === "{") objects.push(new Set());
      else if (token === "[") objects.push(null);
      else if (token === "}" || token === "]") {
        if (objects.length === 2 && intentStart >= 0 && rawIntent === undefined)
          rawIntent = review_json.slice(intentStart, match.index + 1);
        objects.pop();
      } else if (token.startsWith('"') && tokens[i + 1]?.[0] === ":") {
        const keys = objects.at(-1);
        const key = JSON.parse(token) as string;
        if (!keys || keys.has(key)) return false;
        keys.add(key);
        if (objects.length === 1 && key === "intent") {
          const start = tokens[i + 2];
          if (start?.[0] !== "{") return false;
          intentStart = start.index;
        }
      }
    }
    if (stableJson(JSON.parse(review_json)) !== stableJson(body)) return false;
    // The server's normative JSON is the proof. Re-encoding floats or Unicode
    // with JavaScript would change valid Python wire bytes (for example 1.0).
    return (
      rawIntent !== undefined &&
      (await textDigest(review_json)) === review_sha256 &&
      (!row.outcome ||
        (await textDigest(rawIntent)) === row.outcome.intent_sha256)
    );
  } catch {
    return false;
  }
}
