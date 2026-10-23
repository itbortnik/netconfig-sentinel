import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import { date, shortId } from "./format";
import type { PatchDraft } from "./patches";
import type { SourceEvidenceReport } from "./sourceEvidenceReports";
import type {
  CreateSourceRiskAssessment,
  SourceRiskAssessment,
  SourceRiskSummary,
} from "./sourceRiskAssessments";

const names = {
  policy: "Политики",
  peer_group: "Сравнение с peers",
  statistical: "Исходный Forest",
  transformer: "Нейросетевая модель",
  verification: "Сетевая проверка",
};
const bands = {
  low: "Низкий",
  medium: "Средний",
  high: "Высокий",
  critical: "Критический",
};
const reasons = {
  available: "Сохранённое наблюдение доступно",
  not_selected: "Результат не выбран",
  peer_context_unavailable: "Контекст peers отсутствует",
  neural_anomaly_head_disabled: "Голова аномалий выключена",
  legacy_network_protocol: "Историческая запись без направления",
  network_adverse_evidence_unavailable:
    "Нет подтверждённой потери в выбранной сетевой области; результат недоступен для приоритета",
};
const railNames = {
  critical_policy: "Критическая политика: нижняя граница 0,90",
  observed_scoped_loss:
    "Наблюдаемая потеря IPv4 в выбранной области: нижняя граница 0,95",
};
const number = (n: number | null) =>
  n === null
    ? "недоступно"
    : n.toLocaleString("ru-RU", { maximumFractionDigits: 6 });
export function SourceRiskAssessmentPanel({
  client,
  draft,
  report,
  busy: outerBusy,
  onError,
  onGuardChange,
}: {
  client: ApiClient;
  draft: PatchDraft;
  report: SourceEvidenceReport;
  busy: boolean;
  onError: (problem: unknown) => void;
  onGuardChange: (guarded: boolean) => void;
}) {
  const [open, setOpen] = useState(false),
    [working, setWorking] = useState(false),
    [history, setHistory] = useState<SourceRiskSummary[]>([]),
    [offset, setOffset] = useState(0),
    [attempt, setAttempt] = useState<CreateSourceRiskAssessment | null>(null),
    [view, setView] = useState<SourceRiskAssessment | null>(null),
    [uncertain, setUncertain] = useState(false),
    [rejected, setRejected] = useState(false),
    [notStored, setNotStored] = useState(false);
  const alive = useRef(true),
    lock = useRef(false),
    intent = useRef<CreateSourceRiskAssessment | null>(null),
    busy = outerBusy || working;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      onGuardChange(false);
    };
  }, [onGuardChange]);
  useEffect(() => {
    onGuardChange(working || uncertain);
  }, [working, uncertain, onGuardChange]);
  async function operation(action: () => Promise<void>) {
    if (lock.current || outerBusy) return;
    lock.current = true;
    setWorking(true);
    onGuardChange(true);
    try {
      await action();
    } catch (problem) {
      if (alive.current) onError(problem);
    } finally {
      lock.current = false;
      if (alive.current) setWorking(false);
    }
  }
  async function load(next: number) {
    const rows = await client.sourceRiskAssessments(report, next);
    if (alive.current) {
      setHistory(rows);
      setOffset(next);
    }
  }
  async function save() {
    if (intent.current || !client.permits("verify")) return;
    const request: CreateSourceRiskAssessment = {
      version: "source-risk-request-0.1.0",
      assessment_id: crypto.randomUUID(),
      report_sha256: report.review_sha256,
      profile_version: "source-priority-profile-0.1.0",
    };
    intent.current = request;
    setAttempt(request);
    setView(null);
    setUncertain(true);
    setRejected(false);
    setNotStored(false);
    let row: SourceRiskAssessment;
    try {
      row = await client.createSourceRiskAssessment(draft, report, request);
    } catch (problem) {
      if (alive.current)
        setRejected(
          problem instanceof ApiError &&
            [400, 403, 404, 409, 413, 422, 429].includes(problem.status),
        );
      throw problem;
    }
    if (!alive.current) return;
    setView(row);
    setUncertain(false);
    await load(0);
  }
  async function reconcile() {
    const request = intent.current;
    if (!request) return;
    try {
      const row = await client.sourceRiskAssessment(
        draft,
        report,
        request.assessment_id,
        request,
      );
      if (!alive.current) return;
      setView(row);
      setUncertain(false);
      setNotStored(false);
    } catch (problem) {
      if (
        alive.current &&
        rejected &&
        problem instanceof ApiError &&
        problem.status === 404
      )
        setNotStored(true);
      throw problem;
    }
    await load(0);
  }
  async function detail(summary: SourceRiskSummary) {
    const expected =
      intent.current?.assessment_id === summary.assessment_id
        ? intent.current
        : undefined;
    const row = await client.sourceRiskAssessment(
      draft,
      report,
      summary.assessment_id,
      expected,
      summary,
    );
    if (!alive.current) return;
    setView(row);
    if (expected) {
      setUncertain(false);
      setNotStored(false);
    }
  }
  function reset() {
    if (
      busy ||
      !attempt ||
      (uncertain
        ? !(rejected && notStored)
        : view?.assessment_id !== attempt.assessment_id)
    )
      return;
    intent.current = null;
    setAttempt(null);
    setView(null);
    setUncertain(false);
    setRejected(false);
    setNotStored(false);
  }
  return (
    <section
      className="patch-panel"
      aria-label="Экспериментальный приоритет отчёта"
    >
      <h4>Экспериментальный приоритет отчёта</h4>
      <p className="notice warning">
        Отдельная неизменяемая оценка выбранного совместного отчёта. Число от 0
        до 1 — безразмерный инженерный приоритет, не процент, вероятность,
        severity или confidence детектора. Веса и границы не откалиброваны;
        независимое качество не доказано. Модели и движок повторно не
        запускаются.
      </p>
      <p>
        Оценка относится к снимку «после». Сырые числа моделей и итог не
        доказывают качество парного сравнения, улучшение ранжирования или
        сопоставимость разных наборов доступных источников. Согласование,
        применение и общая формальная квалификация не устанавливаются.
      </p>
      <button
        className="button secondary"
        disabled={busy}
        onClick={() =>
          void operation(async () => {
            setOpen(true);
            await load(0);
          })
        }
      >
        {open
          ? "Обновить приоритеты отчёта"
          : "Открыть приоритеты этого отчёта"}
      </button>
      {open && (
        <>
          {working && (
            <p role="status">
              Чтение или сохранение экспериментального приоритета…
            </p>
          )}
          {client.permits("verify") && (
            <button
              className="button secondary"
              disabled={busy || !!attempt}
              onClick={() => void operation(save)}
            >
              Сохранить экспериментальный приоритет
            </button>
          )}
          {attempt && (
            <div aria-label="Запрос экспериментального приоритета">
              <p className="mono">ID оценки: {attempt.assessment_id}</p>
              {uncertain && (
                <p className="notice warning">
                  {rejected
                    ? "Сервер отклонил запрос. Проверьте наличие оценки этого ID."
                    : "Итог сохранения экспериментального приоритета не подтверждён."}{" "}
                  Выбранный отчёт заморожен; повторной отправки POST нет.
                </p>
              )}
              <button
                className="button secondary"
                disabled={busy}
                onClick={() => void operation(reconcile)}
              >
                Прочитать оценку по ID запроса
              </button>
              {rejected && notStored && (
                <>
                  <p>
                    После явного отказа чтение вернуло 404. Доступен явный
                    сброс.
                  </p>
                  <button
                    className="button secondary"
                    disabled={busy}
                    onClick={reset}
                  >
                    Сбросить отклонённый запрос приоритета
                  </button>
                </>
              )}
              {!uncertain && view?.assessment_id === attempt.assessment_id && (
                <button
                  className="button secondary"
                  disabled={busy}
                  onClick={reset}
                >
                  Подготовить новую оценку приоритета
                </button>
              )}
            </div>
          )}
          <ul aria-label="История экспериментальных приоритетов">
            {history.map((row) => (
              <li key={row.assessment_id}>
                <button
                  className="button secondary compact"
                  disabled={busy}
                  onClick={() => void operation(() => detail(row))}
                >
                  Открыть оценку {shortId(row.assessment_id)} ·{" "}
                  {date(row.created_at)} · {number(row.score)}
                </button>
              </li>
            ))}
          </ul>
          {!history.length && <p>Оценок на этой странице нет.</p>}
          <p className="hint">
            Оценок на странице: {history.length}; смещение: {offset}.
          </p>
          {(offset > 0 || history.length === 20) && (
            <div className="pager">
              <button
                className="button secondary compact"
                disabled={busy || offset === 0}
                onClick={() => void operation(() => load(offset - 20))}
              >
                Предыдущие оценки приоритета
              </button>
              <button
                className="button secondary compact"
                disabled={busy || history.length < 20 || offset >= 10000}
                onClick={() => void operation(() => load(offset + 20))}
              >
                Следующие оценки приоритета
              </button>
            </div>
          )}
          {view && <RiskView view={view} />}
        </>
      )}
    </section>
  );
}
function RiskView({ view }: { view: SourceRiskAssessment }) {
  const c = view.composition;
  return (
    <div aria-label="Сохранённый экспериментальный приоритет">
      <h4>Экспериментальный приоритет сохранён</h4>
      <p>
        Приоритет: {number(c.score)}
        {c.band ? ` · ${bands[c.band]}` : ""}. Покрытие:{" "}
        {c.coverage === "partial"
          ? "частичное — общий приоритет недоступен"
          : "полное в поддержанном синтаксисе"}
        .
      </p>
      <p>
        Набор доступных источников:{" "}
        {c.availability_mask.map((s) => names[s]).join(", ")}. Отсутствующий
        источник не заменяется безопасным нулём. Нулевой итог означал бы только
        приоритет в этом наборе источников, а не безопасность всей сети.
      </p>
      {c.coverage === "partial" && (
        <p className="notice warning">
          Сырые наблюдения и применимые ограничения сохранены, но все
          эффективные веса равны нулю, вклады, итог и категория отсутствуют;
          ограничения к итогу не применены.
        </p>
      )}
      <table aria-label="Компоненты экспериментального приоритета">
        <thead>
          <tr>
            <th>Источник</th>
            <th>Наблюдение 0–1</th>
            <th>Вес профиля</th>
            <th>Эффективный вес</th>
            <th>Вклад</th>
            <th>Доступность</th>
          </tr>
        </thead>
        <tbody>
          {c.components.map((row) => (
            <tr key={row.source}>
              <th>{names[row.source]}</th>
              <td>{number(row.raw_score)}</td>
              <td>{number(row.configured_weight)}</td>
              <td>{number(row.effective_weight)}</td>
              <td>{number(row.contribution)}</td>
              <td>{reasons[row.reason]}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        Политики и peers используют самое сильное сохранённое замечание после
        изменения: максимум табличной тяжести и anomaly score, умноженный на
        confidence. Эталон исключён. Критическая политика учитывается во всём
        наборе замечаний, независимо от самого сильного.
      </p>
      <p>
        Forest использует сохранённые числовые наблюдения и инженерный
        показатель уверенности по покрытию парсера и числу обучающих примеров.
        Это не новое замечание детектора.
      </p>
      {c.components.map((row) =>
        row.observation?.kind === "neural" ? (
          <p key={row.source}>
            Нейросеть:{" "}
            {row.observation.anomaly_head_enabled
              ? "используется только сохранённая голова аномалий"
              : "голова аномалий выключена"}
            . Классы: {row.observation.classes.join(", ")}. Смысл цели:{" "}
            {row.observation.target_semantics === "injected_mutation"
              ? "внесённая мутация, а не подтверждённая неисправность"
              : "подтверждённая аномалия"}
            . Эти классы не квалифицированы независимо; category и severity не
            подменяют anomaly score.
          </p>
        ) : null,
      )}
      <p>
        Сеть даёт вклад только при наблюдаемой потере IPv4 в выбранной области и
        подтверждённой очистке ресурсов. Только выигрыш, отсутствие примеров,
        неизвестный итог, ошибка и исторический протокол остаются недоступными,
        а не безопасным нулём. Общие активные точки входа и вывод адреса
        источника по снимку «после» ограничивают область вывода; доступ
        управления, IPv6 и вся сеть не доказаны.
      </p>
      <ul aria-label="Применимые нижние границы приоритета">
        {c.applicable_guardrails.map((g) => (
          <li key={g.kind}>
            {railNames[g.kind]} ·{" "}
            {c.applied_guardrails.some((a) => a.kind === g.kind)
              ? "применена"
              : "сохранена, к итогу не применена"}
          </li>
        ))}
      </ul>
      <p>
        Формальная квалификация: not_proven. Качество доказано: нет. Калибровка:
        нет. Согласовано: нет. Применено: нет.
      </p>
      <p>
        Первая сервисная роль: {view.service_role}; время:{" "}
        {date(view.created_at)}. Личность инженера не удостоверена. Повторное
        чтение или запрос этого ID сохраняет первую роль, время и
        доказательство.
      </p>
      <details>
        <summary>Привязки и полная сохранённая оценка приоритета</summary>
        <p className="mono">
          Профиль: {c.profile_version} · отчёт: {view.report_id} · SHA-256
          отчёта: {view.report_sha256} · SHA-256 оценки: {view.review_sha256}
        </p>
        <pre className="json-view">{JSON.stringify(view, null, 2)}</pre>
      </details>
    </div>
  );
}
