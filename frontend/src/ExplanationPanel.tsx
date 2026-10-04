import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type { AnalysisResult, ExplanationBundle, Finding } from "./contracts";
import { explanationMatches } from "./explanation";

export function ExplanationPanel({
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
  const [bundle, setBundle] = useState<ExplanationBundle | null>(null);
  const [loading, setLoading] = useState(false);
  const mounted = useRef(true);
  const sequence = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      sequence.current += 1;
    };
  }, []);
  async function load() {
    if (busy || loading) return;
    const saved = analysis.explanations.find(
      (item) => item.finding_id === finding.finding_id,
    );
    if (!saved) return;
    const request = ++sequence.current;
    const current = () => mounted.current && request === sequence.current;
    setLoading(true);
    setBundle(null);
    try {
      const result = await client.explain(finding.finding_id, {
        analysis_id: analysis.analysis_id,
        finding_sha256: saved.finding_sha256,
        provider: "local",
      });
      if (!current()) return;
      if (!(await explanationMatches(result, analysis, finding)))
        throw new ApiError(
          0,
          "Источники или объяснение не соответствуют выбранной находке.",
        );
      if (current()) setBundle(result);
    } catch (problem: unknown) {
      if (current()) onError(problem);
    } finally {
      if (current()) setLoading(false);
    }
  }
  return (
    <section className="knowledge-panel" aria-label="Объяснение с источниками">
      <h4>Проверяемые источники</h4>
      <p className="hint">
        LLM недоступна. Доступны локальные документы проекта; внешних вызовов
        нет. Это не документация вендора и не утверждённый эталон.
      </p>
      <button
        className="button secondary"
        disabled={busy || loading}
        onClick={() => void load()}
      >
        {loading ? "Загрузка источников…" : "Показать источники объяснения"}
      </button>
      {loading && (
        <p role="status">Получение разделов для выбранной находки…</p>
      )}
      {bundle && (
        <>
          <p className="hint">
            Подбор по явным ссылкам детектора · {bundle.knowledge_version}.
            Оценки и сохранённое объяснение не изменены.
          </p>
          {bundle.documents.map((chunk) => (
            <details className="knowledge-source" key={chunk.citation}>
              <summary>{chunk.section_title}</summary>
              <p>{chunk.document_title}</p>
              <p className="mono small">{chunk.citation}</p>
              <pre className="knowledge-content">{chunk.content}</pre>
              <p className="hash">SHA-256 документа: {chunk.document_sha256}</p>
              <p className="hash">SHA-256 раздела: {chunk.content_sha256}</p>
            </details>
          ))}
          <details>
            <summary>Привязка источников и ограничения</summary>
            <p className="hash">Каталог: {bundle.knowledge_sha256}</p>
            <p className="hash">Находка: {bundle.finding_sha256}</p>
            <ul>
              {bundle.limitations.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </details>
        </>
      )}
    </section>
  );
}
