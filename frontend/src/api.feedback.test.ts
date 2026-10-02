import { expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./api";
import type { FeedbackSubmission } from "./contracts";

const token = "test-only-memory-bearer-token-32-characters";
const id = "00000000-0000-0000-0000-000000000001";
const body: FeedbackSubmission = {
  feedback_id: id,
  analysis_id: id,
  finding_sha256: "a".repeat(64),
  verdict: "confirmed_anomaly",
  comment: "Verified in the lab, not approved for deployment.",
};
const record = {
  ...body,
  version: "finding-feedback-0.1.0",
  finding_id: id,
  configuration_id: id,
  device_id: id,
  source_sha256: "b".repeat(64),
  created_at: "2026-10-02T00:00:00Z",
  actor: "shared_service_token",
};
it.each([200, 201])(
  "accepts a validated stored assessment or idempotent replay (%s)",
  async (status) => {
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify(record), { status }));
    const api = new ApiClient(token, transport);
    expect(await api.submitFeedback(id, body)).toEqual(record);
    const [url, init] = transport.mock.calls[0]!;
    expect(url).toBe(`/api/v1/findings/${id}/feedback`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify(body));
    expect(init?.headers).toEqual({
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    });
    expect(init?.cache).toBe("no-store");
    expect(init?.credentials).toBe("omit");
    api.close();
  },
);
it("history always includes the explicit analysis scope and bounded pagination", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValue(new Response(JSON.stringify([record])));
  const api = new ApiClient(token, transport);
  expect(await api.feedback(id, id, 20)).toEqual([record]);
  expect(transport.mock.calls[0]![0]).toBe(
    `/api/v1/findings/${id}/feedback?analysis_id=${id}&limit=20&offset=20`,
  );
  api.close();
});
it("does not trust incompatible successful records or reflect private error bodies", async () => {
  const transport = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ ...record, actor: "verified_engineer" })),
    )
    .mockResolvedValueOnce(
      new Response("private-review-comment", { status: 409 }),
    );
  const api = new ApiClient(token, transport);
  await expect(api.submitFeedback(id, body)).rejects.toBeInstanceOf(ApiError);
  await expect(api.submitFeedback(id, body)).rejects.toThrow(
    "Конфликт идентификатора",
  );
  api.close();
});
