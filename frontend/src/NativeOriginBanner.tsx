import { useEffect, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { ConfigurationSnapshot } from "./contracts";
import { nativeOriginSnapshotBound } from "./nativeMaterializations";
import type { NativeMaterialization } from "./nativeMaterializations";

export function NativeOriginBanner({
  snapshot,
  client,
  busy,
  onOpen,
}: {
  snapshot: ConfigurationSnapshot;
  client: ApiClient;
  busy: boolean;
  onOpen: (origin: NativeMaterialization) => void;
}) {
  const [origin, setOrigin] = useState<NativeMaterialization | null>(null);
  const [state, setState] = useState<
    "loading" | "absent" | "unknown" | "generated"
  >("loading");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let current = true;
    setState("loading");
    setOrigin(null);
    void client
      .getNativeOrigin(snapshot.configuration_id)
      .then((row) => {
        if (!nativeOriginSnapshotBound(row, snapshot))
          throw new ApiError(0, "Происхождение не соответствует снимку.");
        if (current) {
          setOrigin(row);
          setState("generated");
        }
      })
      .catch((problem: unknown) => {
        if (current)
          setState(
            problem instanceof ApiError && problem.status === 404
              ? "absent"
              : "unknown",
          );
      });
    return () => {
      current = false;
    };
  }, [client, snapshot, refresh]);
  return (
    <section
      className="panel native-origin-banner"
      aria-label="Происхождение выбранного снимка"
    >
      {state === "loading" && (
        <p role="status">Проверяется сохранённое происхождение снимка…</p>
      )}
      {state === "absent" && (
        <p className="hint">
          Сгенерированное native-происхождение не зарегистрировано. Способ
          получения снимка здесь не установлен.
        </p>
      )}
      {state === "unknown" && (
        <>
          <p className="notice warning" role="status">
            Происхождение снимка неизвестно: сохранённую запись прочитать не
            удалось.
          </p>
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() => setRefresh((n) => n + 1)}
          >
            Повторить чтение происхождения
          </button>
        </>
      )}
      {origin && (
        <>
          <p className="notice warning">
            Сгенерированный снимок из native-кандидата. Наблюдение состояния
            устройства не подтверждено.
          </p>
          <dl className="identifiers">
            <dt>Исходный снимок</dt>
            <dd>{origin.configuration_id}</dd>
            <dt>Native-кандидат</dt>
            <dd>{origin.candidate_id}</dd>
            <dt>Черновик</dt>
            <dd>{origin.patch_id}</dd>
          </dl>
          <p className="hint">
            При создании новая проверка политик, модели и сети не запускалась.
            Формальная квалификация не доказана; утверждение и применение: нет.
          </p>
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={() => onOpen(origin)}
          >
            Открыть связанный обычный черновик
          </button>
        </>
      )}
    </section>
  );
}
