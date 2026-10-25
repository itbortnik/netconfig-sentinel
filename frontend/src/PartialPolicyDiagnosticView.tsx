import type { z } from "zod";
import type { sourcePartialReportSchema } from "./sourceDeterministicRecheck";

export function PartialPolicyDiagnosticView({
  report,
}: {
  report: z.infer<typeof sourcePartialReportSchema>;
}) {
  return (
    <div aria-label="Частичная диагностика политик">
      <h4>Частичная диагностика исходных политик</h4>
      <p className="notice warning">
        Разбор неполный. Вычисление диагностики завершено; полнота разбора и
        синтаксис устройства не подтверждены. Сопоставление изменений
        недоступно: partial_parsing. Общий приоритет и категория недоступны,
        включая случай полного разбора только снимка «после».
      </p>
      <p>
        Каталог: {report.policy_catalog_version}. Эталон, профиль соседей и
        статистическое сравнение не выбраны. Классификация замечаний как
        появившихся, исчезнувших или исправленных недоступна.
      </p>
      {(["before", "after"] as const).map((side) => {
        const s = report[side],
          p = s.parse;
        return (
          <section
            key={side}
            aria-label={
              side === "before" ? "Диагностика до" : "Диагностика после"
            }
          >
            <h5>{side === "before" ? "До изменения" : "После изменения"}</h5>
            <p>
              Покрытие разбора:{" "}
              {p.summary.complete
                ? "полное в поддержанном синтаксисе"
                : "неполное"}
              . Уверенность парсера: {p.summary.confidence}. Неразобранных
              фрагментов: {p.summary.unparsed_count}. Предупреждений:{" "}
              {p.summary.warning_count}. Наблюдений политик:{" "}
              {s.policy_findings.length}.
            </p>
            <p className="mono">
              Исходник: {s.configuration_id} · SHA-256: {s.source_sha256}
            </p>
            <ul aria-label="Местоположения неразобранных фрагментов">
              {p.unknown_locations.map((l, i) => (
                <li key={i} className="mono">
                  Строки: {l.source_lines.join(", ")} · SHA-256 фрагмента:{" "}
                  {l.raw_text_hash} · уверенность парсера: {l.parser_confidence}
                </li>
              ))}
            </ul>
            {p.locations_truncated && (
              <p>Показаны первые 256 местоположений; список сокращён.</p>
            )}
            <ul aria-label="Наблюдаемые замечания политик">
              {s.policy_findings.map((f) => (
                <li key={f.finding_id}>
                  <strong>
                    {f.severity} · {f.category}
                  </strong>
                  : {f.title} · строки:{" "}
                  {f.affected_lines.join(", ") || "не указаны"}
                  <span className="mono"> · ID: {f.finding_id}</span>
                </li>
              ))}
            </ul>
            {!s.policy_findings.length && (
              <p>
                Наблюдений в доступном разборе нет; полнота проверки не
                установлена.
              </p>
            )}
          </section>
        );
      })}
    </div>
  );
}
