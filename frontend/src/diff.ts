import type {
  ConfigurationSnapshot,
  DiffSnapshot,
  SnapshotDiff,
} from "./contracts";

export type DiffSelection = Omit<DiffSnapshot, "projection_sha256">;
export function diffSelection(snapshot: ConfigurationSnapshot): DiffSelection {
  const config = snapshot.canonical;
  return {
    configuration_id: snapshot.configuration_id,
    device_id: snapshot.device_id,
    source_sha256: config.source.sha256,
    created_at: snapshot.created_at,
    vendor: config.device.vendor,
    platform: config.device.platform,
    hostname: config.device.hostname,
    parser_confidence: config.parser_confidence,
    warning_count: config.parse_warnings.length,
    unparsed_count: config.unparsed_fragments.length,
  };
}
export function diffInput(before: DiffSelection, after: DiffSelection) {
  if (
    before.configuration_id === after.configuration_id ||
    before.device_id !== after.device_id ||
    before.vendor !== after.vendor ||
    before.platform !== after.platform ||
    before.hostname !== after.hostname ||
    Date.parse(before.created_at) > Date.parse(after.created_at)
  )
    throw new Error(
      "Для сравнения выберите более ранний снимок того же устройства, не текущий снимок.",
    );
  return before.configuration_id;
}
export function diffBound(
  report: SnapshotDiff,
  before: DiffSelection,
  after: DiffSelection,
) {
  const matches = (received: DiffSnapshot, selected: DiffSelection) =>
    (Object.keys(selected) as (keyof DiffSelection)[]).every((key) =>
      key === "created_at"
        ? Date.parse(received[key]) === Date.parse(selected[key])
        : received[key] === selected[key],
    );
  return matches(report.before, before) && matches(report.after, after);
}
