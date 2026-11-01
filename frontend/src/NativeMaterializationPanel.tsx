import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import { stableJson } from "./contracts";
import type { NativePatchCandidate } from "./nativePatches";
import {
  nativeMaterializationBound,
  nativeMaterializationRequest,
} from "./nativeMaterializations";
import type {
  CreateNativeMaterialization,
  NativeMaterialization,
} from "./nativeMaterializations";

export function NativeMaterializationPanel({
  candidate,
  client,
  busy,
  onError,
  onOpen,
}: {
  candidate: NativePatchCandidate;
  client: ApiClient;
  busy: boolean;
  onError: (problem: unknown) => void;
  onOpen?: (row: NativeMaterialization) => void;
}) {
  const [localConsent, setLocalConsent] = useState(false),
    [retentionConsent, setRetentionConsent] = useState(false);
  const [result, setResult] = useState<NativeMaterialization | null>(null);
  const [working, setWorking] = useState(false),
    [ready, setReady] = useState(false),
    [unknown, setUnknown] = useState(false),
    [notice, setNotice] = useState("");
  const intent = useRef<CreateNativeMaterialization | null>(null),
    alive = useRef(true),
    lock = useRef(false);
  const canCreate = client.permits("draft"),
    disabled = busy || working;
  function accept(
    row: NativeMaterialization,
    expected?: CreateNativeMaterialization,
  ) {
    if (
      !nativeMaterializationBound(row, candidate) ||
      (expected && stableJson(expected) !== stableJson(row.request)) ||
      (result && stableJson(result) !== stableJson(row))
    )
      throw new ApiError(
        0,
        "Созданный черновик не соответствует native-кандидату.",
      );
    setResult(row);
    setUnknown(false);
    setReady(true);
    intent.current = null;
    setNotice(
      "Снимок и черновик сохранены. Новая проверка политик, модели и сети не запускалась.",
    );
  }
  useEffect(() => {
    alive.current = true;
    void client
      .getNativeMaterialization(
        candidate.configuration_id,
        candidate.candidate_id,
      )
      .then((row) => {
        if (alive.current) accept(row);
      })
      .catch((problem: unknown) => {
        if (!alive.current) return;
        if (problem instanceof ApiError && problem.status === 404)
          setReady(true);
        else {
          setNotice(
            "Состояние создания черновика неизвестно. Обновите сохранённый результат.",
          );
          onError(problem);
        }
      });
    return () => {
      alive.current = false;
    };
    // The parent keys this panel by candidate and service session.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, candidate.candidate_id]);
  async function run(action: () => Promise<void>) {
    if (lock.current || busy) return;
    lock.current = true;
    setWorking(true);
    try {
      await action();
    } catch (problem) {
      if (alive.current) onError(problem);
    } finally {
      lock.current = false;
      if (alive.current) setWorking(false);
    }
  }
  async function read() {
    try {
      const row = await client.getNativeMaterialization(
        candidate.configuration_id,
        candidate.candidate_id,
      );
      if (alive.current) accept(row, intent.current ?? undefined);
    } catch (problem) {
      if (
        alive.current &&
        problem instanceof ApiError &&
        problem.status === 404
      ) {
        setReady(true);
        setNotice(
          intent.current
            ? "Запись пока не найдена. Это не подтверждает отмену отправки. Повтор сохранит оба UUID и исходные разрешения."
            : "Сохранённый черновик для кандидата пока не найден.",
        );
        return;
      }
      throw problem;
    }
  }
  async function send(replay = false) {
    if (
      !canCreate ||
      (!replay &&
        (!ready || !localConsent || !retentionConsent || unknown || result))
    )
      return;
    intent.current ??= nativeMaterializationRequest(candidate);
    const request = intent.current;
    setUnknown(true);
    setLocalConsent(false);
    setRetentionConsent(false);
    setNotice("");
    try {
      const row = await client.createNativeMaterialization(
        candidate.configuration_id,
        candidate.candidate_id,
        request,
      );
      if (alive.current) accept(row, request);
    } catch (problem) {
      if (!alive.current) return;
      if (
        !replay &&
        problem instanceof ApiError &&
        problem.status > 0 &&
        problem.status < 500
      ) {
        intent.current = null;
        setUnknown(false);
      } else
        setNotice(
          "Итог создания черновика неизвестен. Прочитайте сохранённый результат перед повтором с теми же UUID.",
        );
      throw problem;
    }
  }
  return (
    <section
      className="native-materialization-panel"
      aria-label="Создание обычного черновика из native-кандидата"
    >
      <h5>Снимок и обычный черновик из кандидата</h5>
      <p className="hint">
        Отдельное действие создаёт новый сгенерированный снимок и черновик
        нормализованных объектов. Политики, модель и сеть при создании повторно
        не проверяются.
      </p>
      {canCreate && !result && (
        <>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={localConsent}
              disabled={disabled || unknown}
              onChange={(e) => setLocalConsent(e.target.checked)}
            />
            Разрешаю локальное создание снимка и обычного черновика из
            выбранного native-кандидата
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={retentionConsent}
              disabled={disabled || unknown}
              onChange={(e) => setRetentionConsent(e.target.checked)}
            />
            Разрешаю новую приватную копию полного исходника кандидата, включая
            посторонние учётные данные; удаление оригинала не удаляет эту копию
          </label>
          <button
            type="button"
            disabled={
              disabled ||
              !ready ||
              unknown ||
              !localConsent ||
              !retentionConsent
            }
            onClick={() => void run(() => send())}
          >
            Создать снимок и обычный черновик
          </button>
        </>
      )}
      {!canCreate && (
        <p className="hint">
          Роль сессии разрешает чтение сохранённого результата.
        </p>
      )}
      <div className="button-row">
        <button
          type="button"
          disabled={disabled}
          onClick={() => void run(read)}
        >
          Прочитать результат создания черновика
        </button>
        {unknown && canCreate && intent.current && (
          <button
            type="button"
            disabled={disabled}
            onClick={() => void run(() => send(true))}
          >
            Повторить создание с теми же UUID
          </button>
        )}
      </div>
      {unknown && intent.current && (
        <p className="hash">
          UUID снимка: {intent.current.after_configuration_id}; UUID черновика:{" "}
          {intent.current.patch_id}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {result && (
        <div aria-label="Созданный обычный черновик">
          <p className="notice warning">
            Происхождение: сгенерированный native-кандидат. Формальная
            квалификация не доказана; утверждение и применение: нет.
          </p>
          <dl className="identifiers">
            <dt>Снимок</dt>
            <dd>{result.after.configuration_id}</dd>
            <dt>Черновик</dt>
            <dd>{result.patch_id}</dd>
            <dt>Запись SHA</dt>
            <dd>{result.review_sha256}</dd>
          </dl>
          {onOpen && (
            <button
              type="button"
              disabled={disabled}
              onClick={() => onOpen(result)}
            >
              Открыть созданный снимок и черновик
            </button>
          )}
        </div>
      )}
    </section>
  );
}
