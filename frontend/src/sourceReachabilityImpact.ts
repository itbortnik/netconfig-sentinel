import { z } from "zod";
import { batfishSchema } from "./modelReviews";

export const reachabilityImpactLimitations = [
  "Returned flows are examples, not all packets or the size of the affected flow space.",
  "Differential queries use ingress locations present and active in both snapshots.",
  "Source IP inference uses the after snapshot; removed ingress locations are not covered.",
  "Successful subnet delivery or exit does not establish delivery to an external device.",
  "No severity, whole-network safety, management access, approval or application is inferred.",
] as const;
const success = new Set(["ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"]);
const disposition = z.enum([
  "ACCEPTED",
  "DELIVERED_TO_SUBNET",
  "EXITS_NETWORK",
  "DENIED_IN",
  "DENIED_OUT",
  "NO_ROUTE",
  "NULL_ROUTED",
  "NEIGHBOR_UNREACHABLE",
  "LOOP",
]);
const ordered = (values: string[]) =>
  values.every((value, index) => index === 0 || values[index - 1]! <= value);
export const reachabilityWitnessSchema = z
  .strictObject({
    flow_sha256: z.string().regex(/^[0-9a-f]{64}(?![\s\S])/),
    before_dispositions: z.array(disposition).min(1).max(16),
    after_dispositions: z.array(disposition).min(1).max(16),
    before_trace_count: z.number().int().min(1).max(16),
    after_trace_count: z.number().int().min(1).max(16),
    direction: z.enum(["loss", "gain"]),
  })
  .refine((row) => {
    const before = row.before_dispositions.some((value) => success.has(value)),
      after = row.after_dispositions.some((value) => success.has(value));
    return (
      row.before_trace_count === row.before_dispositions.length &&
      row.after_trace_count === row.after_dispositions.length &&
      ordered(row.before_dispositions) &&
      ordered(row.after_dispositions) &&
      before !== after &&
      row.direction === (before ? "loss" : "gain")
    );
  });
export const reachabilityImpactSchema = z
  .strictObject({
    version: z.literal("reachability-impact-0.1.0"),
    state: z.enum(["observed", "inconclusive", "not_observed", "unknown"]),
    reason: z.enum([
      "query_completed",
      "empty_reachable_scope",
      "not_run",
      "unsupported_frame",
      "witness_limit_exceeded",
      "incomplete_traces",
      "ambiguous_witness",
      "unknown_disposition",
      "insufficient_information",
      "cleanup_unconfirmed",
    ]),
    direction: z
      .enum([
        "loss_found",
        "gain_found",
        "loss_and_gain_found",
        "no_witnesses_returned",
      ])
      .nullable(),
    lost_witness_count: z.number().int().min(0).max(64).nullable(),
    gained_witness_count: z.number().int().min(0).max(64).nullable(),
    witnesses: z.array(reachabilityWitnessSchema).max(64),
    max_witnesses: z.literal(64),
    max_traces: z.literal(16),
    method: z.literal("differential-success-example-flows-0.1.0"),
    limitations: z.tuple(
      reachabilityImpactLimitations.map((value) => z.literal(value)) as [
        z.ZodLiteral<(typeof reachabilityImpactLimitations)[0]>,
        z.ZodLiteral<(typeof reachabilityImpactLimitations)[1]>,
        z.ZodLiteral<(typeof reachabilityImpactLimitations)[2]>,
        z.ZodLiteral<(typeof reachabilityImpactLimitations)[3]>,
        z.ZodLiteral<(typeof reachabilityImpactLimitations)[4]>,
      ],
    ),
  })
  .refine((row) => {
    const expected = {
      observed: "query_completed",
      inconclusive: "empty_reachable_scope",
      not_observed: "not_run",
    };
    if (row.state === "unknown") {
      if (
        ["query_completed", "empty_reachable_scope", "not_run"].includes(
          row.reason,
        )
      )
        return false;
    } else if (row.reason !== expected[row.state]) return false;
    if (row.state !== "observed")
      return (
        row.direction === null &&
        row.lost_witness_count === null &&
        row.gained_witness_count === null &&
        row.witnesses.length === 0
      );
    const hashes = row.witnesses.map((value) => value.flow_sha256),
      lost = row.witnesses.filter((value) => value.direction === "loss").length,
      gained = row.witnesses.length - lost,
      direction =
        lost && gained
          ? "loss_and_gain_found"
          : lost
            ? "loss_found"
            : gained
              ? "gain_found"
              : "no_witnesses_returned";
    return (
      new Set(hashes).size === hashes.length &&
      ordered(hashes) &&
      row.lost_witness_count === lost &&
      row.gained_witness_count === gained &&
      row.direction === direction
    );
  });
export type ReachabilityImpact = z.infer<typeof reachabilityImpactSchema>;
export const batfishDirectionalExecutionSchema = z
  .strictObject({
    version: z.literal("batfish-execution-0.3.0"),
    result: batfishSchema,
    sdk_version: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}(?![\s\S])/)
      .nullable(),
    sdk_observation: z.enum([
      "observed",
      "not_observed",
      "metadata_unavailable",
    ]),
    reachability_impact: reachabilityImpactSchema,
  })
  .refine((row) => {
    const { result, reachability_impact: impact } = row;
    if (
      (row.sdk_observation === "observed") !== (row.sdk_version !== null) ||
      ([
        "upload_not_authorized",
        "sdk_missing",
        "worker_failed",
        "timeout",
      ].includes(result.reason) &&
        row.sdk_observation !== "not_observed") ||
      (row.sdk_observation === "not_observed" &&
        !["unavailable", "error"].includes(result.status))
    )
      return false;
    if (
      ![
        "inconclusive",
        "differences_found",
        "no_differences_in_scope",
      ].includes(result.status)
    )
      return impact.state === "not_observed" && impact.reason === "not_run";
    if (result.cleanup_complete !== true)
      return (
        impact.state === "unknown" && impact.reason === "cleanup_unconfirmed"
      );
    if (result.status === "inconclusive")
      return (
        impact.state === "inconclusive" &&
        impact.reason === "empty_reachable_scope"
      );
    if (impact.state === "observed")
      return impact.witnesses.length === result.difference_count;
    return (
      impact.state === "unknown" && impact.reason !== "cleanup_unconfirmed"
    );
  });
export const reachabilityDirectionNames = {
  loss_found: "Наблюдены примеры потери успешной доставки",
  gain_found: "Наблюдены примеры появления успешной доставки",
  loss_and_gain_found: "Наблюдены примеры потери и появления успешной доставки",
  no_witnesses_returned: "Запрос не вернул примеров различий",
};
export const reachabilityReasonNames = {
  query_completed: "Запрос выполнен",
  empty_reachable_scope: "Достижимая область пуста; направление не определено",
  not_run: "Направление не наблюдалось: сетевой запрос не выполнен",
  unsupported_frame: "Форма ответа не поддерживается",
  witness_limit_exceeded: "Ответ превышает предел сохранения примеров",
  incomplete_traces: "Набор путей неполон или усечён",
  ambiguous_witness: "Пример не позволяет определить направление",
  unknown_disposition: "В ответе встретился неизвестный исход доставки",
  insufficient_information: "Движку недостаточно информации",
  cleanup_unconfirmed: "Очистка исходников на движке не подтверждена",
};
