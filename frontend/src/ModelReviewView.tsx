import type { SavedModelReview } from "./modelReviews";
import { date, numericScore, percent } from "./format";

const labels: Record<string, string> = {
  human_review_required: "Требуется проверка инженером",
  device_syntax_not_verified: "Синтаксис на устройстве не проверен",
  management_access_not_verified: "Доступ для управления не проверен",
  rollback_not_verified: "Возврат к исходной конфигурации не проверен",
  operational_topology_not_verified: "Рабочая топология не подтверждена",
  execution_not_authenticated_by_report:
    "Отчёт сам по себе не удостоверяет исполнение",
  baseline_approval_not_established: "Утверждение эталона не установлено",
  explicit_scope_not_full_network_qualification:
    "Выбранная область не является проверкой всей сети",
  ml_quality_not_qualified: "Качество ML независимо не подтверждено",
  current_policy_findings: "В кандидате остаются нарушения политик",
  formal_report_not_supplied: "Формальный отчёт не получен",
  formal_query_not_completed: "Формальный запрос не завершён",
  empty_formal_scope: "Выбранная область достижимости пуста",
  reachability_differences_unreviewed: "Обнаружены различия достижимости",
  network_cleanup_unconfirmed: "Удаление временной сети не подтверждено",
  ml_model_not_selected: "ML-модель не выбрана",
  ml_unavailable: "Повторная ML-проверка недоступна",
  ml_selected_category_not_supported:
    "ML-модель не поддерживает категорию этой находки",
  verification_not_completed: "Проверка не завершена",
  formal_scope_not_passed: "Формальная проверка выбранной области не пройдена",
  engine_cleanup_not_confirmed: "Очистка формального движка не подтверждена",
  incomplete_parsing: "Разбор конфигурации неполный",
  policy_regression_or_missing_comparison:
    "Сравнение политик отсутствует или появились новые нарушения",
  selected_ml_not_completed: "Выбранная ML-проверка не выполнена",
  selected_ml_category_not_supported:
    "Нет ML-результата для выбранной категории",
};
export const limitationLabel = (value: string) => labels[value] ?? value;
const formalLabels = {
  unavailable: "Недоступна",
  error: "Ошибка исполнения",
  incomplete: "Неполная инициализация",
  inconclusive: "Пустая область — результат не определён",
  differences_found: "Обнаружены различия",
  no_differences_in_scope: "Различий в выбранной непустой области не найдено",
};

export function ModelReviewView({ run }: { run: SavedModelReview }) {
  const report = run.report,
    preflight = report?.local_review.preflight,
    engine = report?.network_result?.batfish;
  return (
    <section aria-label="Отчёт проверки модельного кандидата">
      <h4>Сохранённая проверка кандидата</h4>
      <p role="status">
        {run.execution_status === "running"
          ? "Исполнение не завершено; результат не подтверждён."
          : run.execution_status === "failed"
            ? "Исполнение завершилось ошибкой; успешного отчёта нет."
            : "Отчёт сохранён; требуется решение инженера."}
      </p>
      <p className="hint">
        {date(run.created_at)} · изменения не применялись. Выбранные снимки
        закреплены при проверке, не при генерации.
      </p>
      <dl className="identifiers">
        <dt>Проверка</dt>
        <dd>{run.verification_id}</dd>
        <dt>Hash отчёта сервера</dt>
        <dd>{run.review_sha256}</dd>
        <dt>Область</dt>
        <dd>
          {run.request.scope.start_node} → {run.request.scope.destination}
        </dd>
      </dl>
      {preflight && (
        <>
          <h5>Локальные проверки — факты</h5>
          <dl className="identifiers">
            <dt>Повторный разбор до / после</dt>
            <dd>
              {preflight.before.complete ? "Полный" : "Неполный"} /{" "}
              {preflight.after.complete ? "Полный" : "Неполный"}
            </dd>
            <dt>Доверие парсера до / после</dt>
            <dd>
              {percent(preflight.before.confidence)} /{" "}
              {percent(preflight.after.confidence)}
            </dd>
            <dt>Неизвестные фрагменты до / после</dt>
            <dd>
              {preflight.before.unparsed_count} /{" "}
              {preflight.after.unparsed_count}
            </dd>
            <dt>Политики до / после</dt>
            <dd>
              {preflight.before_policy_findings.length} /{" "}
              {preflight.after_policy_findings.length}
            </dd>
            <dt>Новые / устранённые нарушения</dt>
            <dd>
              {preflight.policy_changes
                ? `${preflight.policy_changes.introduced.length} / ${preflight.policy_changes.resolved.length}`
                : "Сравнение недоступно"}
            </dd>
            <dt>Сравнение с выбранным эталоном</dt>
            <dd>
              {preflight.reference_status === "completed"
                ? "Выполнено для поддерживаемых свойств"
                : "Недоступно"}
            </dd>
          </dl>
          <details>
            <summary>Изменённые диапазоны строк</summary>
            <p className="hint">
              Нумерация с 1; диапазоны включают только изменённые строки. Это не
              синтаксическая проверка оборудованием.
            </p>
            <ul>
              {report.local_review.proposal.changes.map((change, index) => (
                <li key={index}>
                  {change.operation}: до{" "}
                  {change.before_start === change.before_end
                    ? "пусто"
                    : `${change.before_start + 1}–${change.before_end}`}
                  ; после{" "}
                  {change.after_start === change.after_end
                    ? "пусто"
                    : `${change.after_start + 1}–${change.after_end}`}
                </li>
              ))}
            </ul>
          </details>
          <details>
            <summary>Нарушения политик в кандидате</summary>
            <ul>
              {preflight.after_policy_findings.map((row) => (
                <li key={row.finding_id}>
                  {row.title} · {row.category} · строки{" "}
                  {row.affected_lines.join(", ") || "не указаны"}
                </li>
              ))}
            </ul>
          </details>
        </>
      )}
      <h5>Формальная проверка</h5>
      <p>{engine ? formalLabels[engine.status] : "Batfish не запускался."}</p>
      {engine && (
        <>
          <dl className="identifiers">
            <dt>Движок</dt>
            <dd>{engine.engine_version ?? "Версия не получена"}</dd>
            <dt>Достижимые потоки до / после</dt>
            <dd>
              {engine.before_reachable_count ?? "Нет результата"} /{" "}
              {engine.after_reachable_count ?? "Нет результата"}
            </dd>
            <dt>Различия</dt>
            <dd>{engine.difference_count ?? "Нет результата"}</dd>
            <dt>Очистка временной сети</dt>
            <dd>
              {engine.cleanup_complete === true
                ? "Подтверждена"
                : "Не подтверждена"}
            </dd>
          </dl>
          <ul>
            {engine.limitations.map((value, index) => (
              <li key={index}>{value}</li>
            ))}
          </ul>
        </>
      )}
      <p className="hint">
        Проверка IPv4-достижимости не подтверждает синтаксис устройства, работу
        SSH или сохранение административного доступа.
      </p>
      <h5>Повторные ML-оценки</h5>
      <p>
        {run.ml_execution === "completed"
          ? "Выбранная модель выполнена. Оценки экспериментальные и не калиброваны."
          : run.ml_execution === "unavailable"
            ? "Выбранная модель недоступна; локальный отчёт сохранён."
            : "Transformer не выбран."}
      </p>
      {report?.ml_reviews.map((row, index) => (
        <details key={index}>
          <summary>
            ML-модель {index + 1} · {row.transformer.status}
          </summary>
          <p className="hash">
            {row.transformer.model_sha256 ?? "Модель не выбрана"}
          </p>
          <p>
            Оценка до / после:{" "}
            {row.transformer.before?.anomaly_score != null
              ? numericScore(row.transformer.before.anomaly_score)
              : "Нет оценки"}{" "}
            /{" "}
            {row.transformer.after?.anomaly_score != null
              ? numericScore(row.transformer.after.anomaly_score)
              : "Нет оценки"}
          </p>
          <p className="hint">
            Не входит в сохранённый риск. Не доказывает качество или
            безопасность кандидата.
          </p>
          <pre>
            {JSON.stringify(
              {
                before_categories: row.transformer.before?.category_scores,
                after_categories: row.transformer.after?.category_scores,
                before_severity: row.transformer.before?.severity_scores,
                after_severity: row.transformer.after?.severity_scores,
              },
              null,
              2,
            )}
          </pre>
        </details>
      ))}
      {run.statistical_recheck && (
        <details>
          <summary>Повторная оценка Isolation Forest</summary>
          <p className="hash">
            Модель: {run.statistical_recheck.model_id} ·{" "}
            {run.statistical_recheck.artifact_sha256}
          </p>
          <p>
            Оценка до / после:{" "}
            {numericScore(run.statistical_recheck.before_score_samples)} /{" "}
            {numericScore(run.statistical_recheck.after_score_samples)}.
          </p>
          <p>
            Метка до / после: {run.statistical_recheck.before_prediction} /{" "}
            {run.statistical_recheck.after_prediction}. Калибровка и качество не
            подтверждены.
          </p>
        </details>
      )}
      <h5>Что препятствует утверждению</h5>
      {run.approval_blockers.length ? (
        <ul>
          {run.approval_blockers.map((value) => (
            <li key={value}>{limitationLabel(value)}</li>
          ))}
        </ul>
      ) : (
        <p>
          Автоматические ограничения сняты только для этой области. Нужны
          независимые проверки и явное решение инженера.
        </p>
      )}
      {report && (
        <details open>
          <summary>Оставшиеся ограничения</summary>
          <ul>
            {report.missing_checks.map((value) => (
              <li key={value}>{limitationLabel(value)}</li>
            ))}
          </ul>
        </details>
      )}
      <details>
        <summary>Снимки выбранной сети</summary>
        <ul>
          {run.network.map((row) => (
            <li key={row.configuration_id}>
              <span className="mono">{row.configuration_id}</span>
              <p className="hash">{row.source_sha256}</p>
            </li>
          ))}
        </ul>
      </details>
    </section>
  );
}
