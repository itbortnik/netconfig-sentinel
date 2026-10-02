import { feedbackSubmissionSchema } from "./contracts";
import type {
  AnalysisResult,
  FeedbackRecord,
  FeedbackSubmission,
  FeedbackVerdict,
  Finding,
} from "./contracts";

export const verdictLabels: Record<FeedbackVerdict, string> = {
  confirmed_anomaly: "Аномалия подтверждена",
  false_positive: "Ложное срабатывание",
  needs_investigation: "Нужна проверка",
};
export type FeedbackTarget = Pick<
  FeedbackRecord,
  | "analysis_id"
  | "configuration_id"
  | "device_id"
  | "source_sha256"
  | "finding_id"
  | "finding_sha256"
>;

export function feedbackTarget(
  analysis: AnalysisResult,
  finding: Finding,
): FeedbackTarget {
  const explanation = analysis.explanations.find(
    (item) => item.finding_id === finding.finding_id,
  );
  if (
    !explanation ||
    !analysis.findings.some((item) => item.finding_id === finding.finding_id)
  )
    throw new Error("Находка не принадлежит выбранному анализу.");
  return {
    analysis_id: analysis.analysis_id,
    configuration_id: analysis.configuration_id,
    device_id: analysis.device_id,
    source_sha256: analysis.source_sha256,
    finding_id: finding.finding_id,
    finding_sha256: explanation.finding_sha256,
  };
}
export function feedbackMatches(
  record: FeedbackRecord,
  target: FeedbackTarget,
): boolean {
  return (Object.keys(target) as (keyof FeedbackTarget)[]).every(
    (key) => record[key] === target[key],
  );
}
export function sameSubmission(
  record: FeedbackSubmission,
  expected: FeedbackSubmission,
): boolean {
  return (Object.keys(expected) as (keyof FeedbackSubmission)[]).every(
    (key) => record[key] === expected[key],
  );
}
export function prepareFeedback(
  target: FeedbackTarget,
  verdict: FeedbackVerdict,
  comment: string,
  previous: FeedbackSubmission | null,
): FeedbackSubmission {
  const fields = {
    analysis_id: target.analysis_id,
    finding_sha256: target.finding_sha256,
    verdict,
    comment: comment.trim(),
  };
  const candidate = {
    ...fields,
    feedback_id: previous?.feedback_id ?? crypto.randomUUID(),
  };
  const validated = feedbackSubmissionSchema.safeParse(candidate);
  if (!validated.success)
    throw new Error(
      "Введите оценку и комментарий: 1–2000 символов без управляющих знаков.",
    );
  return previous && sameSubmission(validated.data, previous)
    ? previous
    : { ...validated.data, feedback_id: crypto.randomUUID() };
}
