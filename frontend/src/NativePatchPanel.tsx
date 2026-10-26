import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { AnalysisResult, Finding } from "./contracts";
import { stableJson } from "./contracts";
import {
  nativeCandidateBound,
  nativeCommands,
  nativePatchRequest,
  nativeSelectionBound,
} from "./nativePatches";
import type {
  GenerateNativePatch,
  NativePatchCandidate,
  NativePatchSelection,
  NativePatchSummary,
} from "./nativePatches";
import { date } from "./format";

const invalid = () =>
  new ApiError(
    0,
    "Native-кандидат не соответствует выбранному анализу и находке.",
  );
const uncertainFailure = (problem: unknown) =>
  !(problem instanceof ApiError) ||
  problem.status === 0 ||
  problem.status >= 500;

export function NativePatchPanel({
  analysis,
  finding,
  client,
  busy,
  onError,
}: {
  analysis: AnalysisResult;
  finding: Finding;
  client: ApiClient;
  busy: boolean;
  onError: (problem: unknown) => void;
}) {
  const [open, setOpen] = useState(false),
    [loading, setLoading] = useState(false);
  const [selection, setSelection] = useState<NativePatchSelection | null>(null);
  const [history, setHistory] = useState<NativePatchSummary[]>([]);
  const [offset, setOffset] = useState(0),
    [count, setCount] = useState(0);
  const [candidate, setCandidate] = useState<NativePatchCandidate | null>(null);
  const [allowGeneration, setAllowGeneration] = useState(false),
    [allowRetention, setAllowRetention] = useState(false);
  const [uncertain, setUncertain] = useState(false),
    [notice, setNotice] = useState("");
  const intent = useRef<GenerateNativePatch | null>(null),
    lock = useRef(false),
    epoch = useRef(0);
  useEffect(
    () => () => {
      epoch.current++;
    },
    [client, analysis.analysis_id, finding.finding_id],
  );
  const canDraft = client.permits("draft");
  const disabled = busy || loading;
  async function run(action: (current: () => boolean) => Promise<void>) {
    if (lock.current) return;
    lock.current = true;
    setLoading(true);
    const started = epoch.current;
    const current = () => started === epoch.current;
    try {
      await action(current);
    } catch (problem) {
      if (current()) onError(problem);
    } finally {
      if (current()) {
        lock.current = false;
        setLoading(false);
      }
    }
  }
  function accept(row: NativePatchCandidate, request?: GenerateNativePatch) {
    if (
      !nativeCandidateBound(row, analysis, finding, selection ?? undefined) ||
      (request && stableJson(row.request) !== stableJson(request)) ||
      (candidate?.candidate_id === row.candidate_id &&
        stableJson(candidate) !== stableJson(row))
    )
      throw invalid();
    setCandidate(row);
    intent.current = null;
    setUncertain(false);
    setNotice(
      "Кандидат сохранён. Требуется рассмотрение инженером; формальная квалификация не доказана.",
    );
  }
  async function load(next: number, current: () => boolean) {
    const rows = await client.nativePatches(analysis.configuration_id, next);
    if (!current()) return;
    // The server paginates all candidates for this source. Filter only after preserving its page count.
    setHistory(
      rows.filter(
        (row) =>
          row.analysis_id === analysis.analysis_id &&
          row.finding_id === finding.finding_id,
      ),
    );
    setCount(rows.length);
    setOffset(next);
  }
  async function initialize(current: () => boolean) {
    setOpen(true);
    const results = await Promise.allSettled([
      load(0, current),
      client.nativePatchSelection(
        analysis.configuration_id,
        analysis.analysis_id,
      ),
    ]);
    if (!current()) return;
    const selected = results[1];
    if (selected.status === "fulfilled") {
      if (!nativeSelectionBound(selected.value, analysis)) throw invalid();
      setSelection(selected.value);
    } else {
      setSelection(null);
      onError(selected.reason);
    }
    if (results[0].status === "rejected") throw results[0].reason;
  }
  async function send(
    request: GenerateNativePatch,
    current: () => boolean,
    replay = false,
  ) {
    intent.current = request;
    setUncertain(true);
    setAllowGeneration(false);
    setAllowRetention(false);
    setNotice("");
    try {
      const row = await client.generateNativePatch(
        analysis.configuration_id,
        request,
      );
      if (!current()) return;
      accept(row, request);
    } catch (problem) {
      if (!current()) return;
      if (!replay && !uncertainFailure(problem)) {
        intent.current = null;
        setUncertain(false);
      } else
        setNotice(
          "Итог отправки неизвестен. Прочитайте результат по тому же UUID. Если записи пока нет, можно повторить только сохранённый запрос с тем же UUID.",
        );
      throw problem;
    }
  }
  async function reconcile(current: () => boolean) {
    const request = intent.current;
    if (!request) return;
    try {
      const row = await client.nativePatch(
        analysis.configuration_id,
        request.candidate_id,
        request,
      );
      if (current()) accept(row, request);
    } catch (problem) {
      if (current() && problem instanceof ApiError && problem.status === 404) {
        setNotice(
          "Сохранённая запись пока не найдена. Это не подтверждает отмену отправки. Повтор использует тот же UUID и исходные разрешения.",
        );
        return;
      }
      throw problem;
    }
  }
  const report = candidate?.metadata.review.preflight;
  return (
    <section
      className="native-patch-panel"
      aria-label="Native-кандидат без модели"
    >
      <h4>Исправление Telnet без модели</h4>
      <p className="hint">
        Детерминированный кандидат по сохранённому оригиналу. Отдельный сценарий
        не требует локальной модели. Доступны команды, локальное сравнение
        политик и история.
      </p>
      <p className="notice warning">
        Оригинал — локальная опорная версия, его утверждение как эталона не
        доказано. Синтаксис устройства, доступ управления, откат и формальная
        проверка не подтверждены. Применение не поддерживается.
      </p>
      {!open ? (
        <button
          type="button"
          disabled={disabled}
          onClick={() => void run(initialize)}
        >
          Открыть native-кандидаты
        </button>
      ) : (
        <>
          {canDraft ? (
            <>
              <p className="hint">
                Для нового кандидата нужны два отдельных разрешения. Доступность
                сохранённого оригинала и пригодность находки сервер проверит при
                создании.
              </p>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={allowGeneration}
                  disabled={disabled || uncertain}
                  onChange={(e) => setAllowGeneration(e.target.checked)}
                />
                Разрешаю локальное создание native-кандидата из сохранённого
                оригинала
              </label>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={allowRetention}
                  disabled={disabled || uncertain}
                  onChange={(e) => setAllowRetention(e.target.checked)}
                />
                Разрешаю приватное хранение полного оригинала и кандидата,
                включая посторонние учётные данные; удаление сохранённого
                исходника не удаляет эти копии
              </label>
              <div className="button-row">
                <button
                  type="button"
                  disabled={
                    disabled ||
                    uncertain ||
                    !selection ||
                    !allowGeneration ||
                    !allowRetention
                  }
                  onClick={() =>
                    void run((current) =>
                      send(
                        nativePatchRequest(
                          selection!,
                          finding,
                          crypto.randomUUID(),
                        ),
                        current,
                      ),
                    )
                  }
                >
                  Создать native-кандидат
                </button>
              </div>
              {!selection && (
                <p className="hint">
                  Привязки нового запроса пока недоступны. Историю можно читать
                  отдельно.
                </p>
              )}
            </>
          ) : (
            <p className="hint">
              Роль сессии разрешает просмотр истории. Создание доступно инженеру
              и администратору.
            </p>
          )}
          {uncertain && (
            <div className="native-uncertain" role="status">
              <p>
                UUID отправки:{" "}
                <span className="hash">{intent.current?.candidate_id}</span>
              </p>
              <div className="button-row">
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => void run(reconcile)}
                >
                  Прочитать результат native-отправки
                </button>
                {canDraft && (
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() =>
                      void run((current) =>
                        intent.current
                          ? send(intent.current, current, true)
                          : Promise.resolve(),
                      )
                    }
                  >
                    Повторить native-запрос с тем же UUID
                  </button>
                )}
              </div>
            </div>
          )}
          {notice && (
            <p className="notice" role="status">
              {notice}
            </p>
          )}
          <h5>Сохранённая история этой находки</h5>
          <div className="button-row">
            <button
              type="button"
              disabled={disabled}
              onClick={() => void run((current) => load(offset, current))}
            >
              Обновить native-историю
            </button>
          </div>
          <div className="history-items">
            {history.map((row) => (
              <button
                type="button"
                className="history-item"
                key={row.candidate_id}
                disabled={disabled || uncertain}
                onClick={() =>
                  void run(async (current) => {
                    const saved = await client.nativePatch(
                      analysis.configuration_id,
                      row.candidate_id,
                      undefined,
                      row,
                    );
                    if (current()) accept(saved);
                  })
                }
              >
                Открыть native-кандидат {row.candidate_id.slice(0, 8)} ·{" "}
                {date(row.created_at)} · требуется рассмотрение
              </button>
            ))}
          </div>
          {history.length === 0 && (
            <p className="hint">
              На этой странице кандидатов выбранной находки нет.
            </p>
          )}
          <div className="button-row">
            <button
              type="button"
              disabled={disabled || offset === 0}
              onClick={() =>
                void run((current) => load(Math.max(0, offset - 20), current))
              }
            >
              Предыдущие native-кандидаты
            </button>
            <button
              type="button"
              disabled={disabled || count < 20 || offset >= 10000}
              onClick={() => void run((current) => load(offset + 20, current))}
            >
              Следующие native-кандидаты
            </button>
          </div>
          {candidate && report && (
            <div aria-label="Сохранённый native-кандидат">
              <h5>Сохранённый кандидат — требуется рассмотрение</h5>
              <dl className="identifiers">
                <dt>UUID</dt>
                <dd>{candidate.candidate_id}</dd>
                <dt>Сервисная роль</dt>
                <dd>{candidate.service_role}</dd>
                <dt>Генератор</dt>
                <dd>{candidate.generator_version}</dd>
                <dt>Оригинал SHA</dt>
                <dd>{candidate.source.source_sha256}</dd>
                <dt>Кандидат SHA</dt>
                <dd>{candidate.metadata.review.proposal.after_sha256}</dd>
                <dt>Запись SHA</dt>
                <dd>{candidate.review_sha256}</dd>
              </dl>
              <p className="hint">
                Привязка записи проверена. Она не удостоверяет личность
                инженера, качество исправления или истинность разметки.
                Утверждение и применение: нет.
              </p>
              <h5>Команды для рассмотрения</h5>
              <pre className="native-commands">
                {nativeCommands(candidate.metadata).join("\n")}
              </pre>
              <p className="hint">
                Контекст команд:{" "}
                {candidate.metadata.review.proposal.vendor === "cisco"
                  ? "Cisco IOS, конфигурация VTY"
                  : "JunOS, режим конфигурации"}
                . На устройство команды не отправляются.
              </p>
              <p>
                Локальный разбор: до и после полный. Политик до:{" "}
                {report.before_policy_findings.length}; после:{" "}
                {report.after_policy_findings.length}. Устранено:{" "}
                {report.policy_changes?.resolved.length}; добавлено:{" "}
                {report.policy_changes?.introduced.length}.
              </p>
              <p className="notice warning">
                Это локальный результат парсера и политик. Формальная
                квалификация не доказана; качество и оценки не калиброваны.
                Нужны проверка синтаксиса устройства, доступа управления,
                отката, утверждения эталона, независимого качества и
                рассмотрение инженером.
              </p>
              <ul className="native-edits">
                {candidate.metadata.edits.map((e) => (
                  <li key={e.source_line}>
                    Строка {e.source_line}:{" "}
                    {e.kind === "cisco_vty_ssh_only"
                      ? `VTY ${e.vty!.first}–${e.vty!.last}, оставить SSH`
                      : "удалить явный сервис Telnet"}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}
