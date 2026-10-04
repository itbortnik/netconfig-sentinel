import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type {
  AnalysisResult,
  ExplanationBundle,
  Finding,
  ModelExplanation,
  ExplanationCapabilities,
} from "./contracts";
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
  const [bundle, setBundle] = useState<
    ExplanationBundle | ModelExplanation | null
  >(null);
  const [capabilities, setCapabilities] =
    useState<ExplanationCapabilities | null>(null);
  const [permission, setPermission] = useState(false);
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
  useEffect(() => {
    let alive = true;
    void client
      .explanationCapabilities()
      .then((received) => {
        if (alive) setCapabilities(received);
      })
      .catch((problem: unknown) => {
        if (alive && problem instanceof ApiError && problem.status === 401)
          onError(problem);
      });
    return () => {
      alive = false;
    };
  }, [client, onError]);
  async function load(model = false) {
    if (busy || loading) return;
    if (
      model &&
      (!client.permits("model_explanation") ||
        !permission ||
        capabilities?.local_model !== "configured")
    )
      return;
    const saved = analysis.explanations.find(
      (item) => item.finding_id === finding.finding_id,
    );
    if (!saved) return;
    const request = ++sequence.current;
    const current = () => mounted.current && request === sequence.current;
    setLoading(true);
    setBundle(null);
    try {
      const options = {
        analysis_id: analysis.analysis_id,
        finding_sha256: saved.finding_sha256,
      };
      const result = model
        ? await client.explainModel(finding.finding_id, {
            ...options,
            provider: "llm",
            allow_local_model_context: true,
          })
        : await client.explain(finding.finding_id, {
            ...options,
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
        {capabilities?.local_model === "configured"
          ? "Локальная модель настроена. Её работоспособность проверяется только по отдельному запросу."
          : "LLM недоступна без отдельной настройки сервера."}{" "}
        Доступны локальные документы проекта. Это не документация вендора и не
        утверждённый эталон.
      </p>
      <button
        className="button secondary"
        disabled={busy || loading}
        onClick={() => void load(false)}
      >
        {loading ? "Загрузка источников…" : "Показать источники объяснения"}
      </button>
      {capabilities?.local_model === "configured" &&
        client.permits("model_explanation") && (
          <div className="model-explanation-controls">
            <p className="notice warning">
              В модель на этом компьютере будут отправлены псевдонимизированные
              факты и публичные разделы документов. Числа, hashes и номера строк
              сохраняются и могут быть конфиденциальны. Полный файл и
              неизвестные команды не передаются.
            </p>
            <label>
              <input
                type="checkbox"
                checked={permission}
                disabled={busy || loading}
                onChange={(event) => setPermission(event.target.checked)}
              />{" "}
              Разрешаю передачу этого контекста локальной модели
            </label>
            <button
              className="button secondary"
              disabled={busy || loading || !permission}
              onClick={() => void load(true)}
            >
              Запросить черновик у локальной модели
            </button>
          </div>
        )}
      {loading && (
        <p role="status">Получение разделов для выбранной находки…</p>
      )}
      {bundle && (
        <>
          <p className="hint">
            Подбор по явным ссылкам детектора · {bundle.knowledge_version}.
            Оценки и сохранённое объяснение не изменены.
          </p>
          {"answer" in bundle && (
            <div aria-label="Черновик объяснения модели">
              <h4>Черновик модели — непроверенный текст</h4>
              <p className="notice warning">
                Требуется проверка инженером. Цитаты и формат проверены,
                истинность текста не установлена. Риск, находка и формальная
                проверка не изменены.
              </p>
              <p>{bundle.answer.summary}</p>
              <pre>{bundle.answer.technical_explanation}</pre>
              <h5>Возможное влияние — гипотезы</h5>
              <ul>
                {bundle.answer.possible_impact.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
              <h5>Рекомендация для рассмотрения</h5>
              <pre>{bundle.answer.recommendation}</pre>
              <h5>Допущения</h5>
              <ul>
                {bundle.answer.assumptions.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
              <h5>Недостающие сведения</h5>
              <ul>
                {bundle.answer.missing_information.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
              <p className="hint">
                Исполняемый патч не создаётся. Ответ не сохранён как новый
                анализ.
              </p>
              <details>
                <summary>Привязка ответа модели</summary>
                <p>Настроенный alias: {bundle.model_alias}</p>
                <p className="hash">Контекст: {bundle.context_sha256}</p>
                <p>{bundle.privacy_version}</p>
                <ul>
                  {bundle.answer.citations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </details>
            </div>
          )}
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
