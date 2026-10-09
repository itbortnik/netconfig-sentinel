import type { ParserCoverage } from "./parserCoverage";
import { percent } from "./format";

export function ParserCoverageView({
  report,
}: {
  report?: ParserCoverage | null;
}) {
  return (
    <section aria-labelledby="parser-coverage-heading">
      <h3 id="parser-coverage-heading">Покрытие разбора исходных строк</h3>
      {report ? (
        <>
          <dl className="metrics">
            <div>
              <dt>Доля неподдержанных строк</dt>
              <dd>
                {report.unparsed_fraction === null
                  ? "Нет командных строк"
                  : percent(report.unparsed_fraction)}
              </dd>
            </div>
            <div>
              <dt>Принято адаптером</dt>
              <dd>{report.accepted_units}</dd>
            </div>
            <div>
              <dt>Неподдержанные строки</dt>
              <dd>{report.unparsed_units}</dd>
            </div>
            <div>
              <dt>Командные строки</dt>
              <dd>{report.command_units}</dd>
            </div>
          </dl>
          <p className="hint">
            Всего строк: {report.source_line_count} · Структурные:{" "}
            {report.structural_units} · Пустые/комментарии:{" "}
            {report.ignored_lines}
          </p>
          <p className="hint">
            Доля = неподдержанные / (принятые + неподдержанные). Заголовки
            блоков и повторные настройки считаются отдельно; структурные строки
            и комментарии исключены. Это измерение строк текущего адаптера, не
            универсальный подсчёт vendor-команд и не оценка доверия.
          </p>
          <p className="hint">
            «Принято» не означает полную семантическую нормализацию, проверенный
            синтаксис или безопасность. Формат set и иерархические блоки имеют
            разные единицы подсчёта.
          </p>
          <details>
            <summary>Версия и привязка отчёта</summary>
            <p className="muted">
              {report.version} · {report.adapter_version}
            </p>
            <dl className="identifiers">
              <dt>SHA-256 исходника</dt>
              <dd>{report.source_sha256}</dd>
            </dl>
            <p className="hint">
              Отчёт содержит только номера, статусы и hashes строк, без
              исходного текста. Hashes также могут быть конфиденциальными.
            </p>
          </details>
        </>
      ) : (
        <p className="hint">
          Покрытие не измерено для этого исторического снимка. Долю неизвестных
          строк нельзя восстановить из доверия парсера; исходник автоматически
          не пересчитывается.
        </p>
      )}
    </section>
  );
}
