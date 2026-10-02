import type { AnalysisOptions, ConfigurationSnapshot } from "./contracts";

export type SelectedSnapshot = {
  id: string;
  device: string;
  hostname: string | null;
  hash: string;
  created: string;
  group: string | null;
  complete: boolean;
};

export function selectedSnapshot(
  snapshot: ConfigurationSnapshot,
): SelectedSnapshot {
  const config = snapshot.canonical;
  const device = config.device;
  return {
    id: snapshot.configuration_id,
    device: snapshot.device_id,
    hostname: device.hostname,
    hash: config.source.sha256,
    created: snapshot.created_at,
    group:
      device.role && device.site_class && device.service_profile
        ? JSON.stringify([
            device.vendor,
            device.platform,
            device.role,
            device.site_class,
            device.service_profile,
          ])
        : null,
    complete:
      config.parser_confidence === 1 &&
      config.parse_warnings.length === 0 &&
      config.unparsed_fragments.length === 0,
  };
}

export function comparisonOptions(
  current: SelectedSnapshot,
  reference: SelectedSnapshot | null,
  peers: SelectedSnapshot[],
): AnalysisOptions | undefined {
  if (!reference && peers.length === 0) return undefined;
  if (
    reference &&
    (reference.device !== current.device ||
      reference.id === current.id ||
      Date.parse(reference.created) > Date.parse(current.created) ||
      !reference.complete ||
      !current.complete)
  )
    throw new Error(
      "Эталон должен быть более ранним, полностью разобранным снимком того же устройства. Текущий снимок тоже должен быть разобран полностью.",
    );
  if (peers.length > 0) {
    if (peers.length < 3 || peers.length > 20)
      throw new Error("Выберите 3–20 разных устройств для группы сравнения.");
    if (
      !current.group ||
      !current.hostname ||
      peers.some(
        (peer) =>
          !peer.complete ||
          peer.group !== current.group ||
          !peer.hostname ||
          peer.hostname === current.hostname ||
          peer.device === current.device ||
          Date.parse(peer.created) > Date.parse(current.created),
      )
    )
      throw new Error(
        "Группа должна совпадать по vendor, platform и трём меткам. Используйте более ранние полностью разобранные снимки других устройств.",
      );
    if (
      new Set(peers.map((peer) => peer.device)).size !== peers.length ||
      new Set(peers.map((peer) => peer.hash)).size !== peers.length ||
      new Set(peers.map((peer) => peer.hostname)).size !== peers.length
    )
      throw new Error(
        "Нельзя считать несколько версий или копий одного устройства разными peers.",
      );
  }
  return {
    ...(reference ? { reference_configuration_id: reference.id } : {}),
    ...(peers.length
      ? { peer_configuration_ids: peers.map((peer) => peer.id) }
      : {}),
  };
}
