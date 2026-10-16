import { useEffect, useReducer, useRef, useState } from "react";
import { ApiClient, ApiError } from "./api";
import type {
  AnalysisResult,
  ExplanationBundle,
  Finding,
  ModelExplanation,
  ExplanationCapabilities,
  ConfigurationSnapshot,
} from "./contracts";
import { explanationMatches } from "./explanation";
import {
  ExplanationRequestGate,
  groundedExplanationMatches,
  groundedExplanationPresentation,
  sameExplanationScope,
} from "./groundedExplanation";
import type {
  GroundedExplanation,
  GroundedExplanationCapabilities,
  ExplanationRequestScope,
} from "./groundedExplanation";

export function ExplanationPanel({
  analysis,
  finding,
  snapshot,
  client,
  busy,
  onError,
}: {
  analysis: AnalysisResult;
  finding: Finding;
  snapshot?: ConfigurationSnapshot | null;
  client: ApiClient;
  busy: boolean;
  onError: (problem: unknown) => void;
}) {
  const [receivedBundle, setBundle] = useState<{
    value: ExplanationBundle | ModelExplanation | GroundedExplanation;
    scope: ExplanationRequestScope;
  } | null>(null);
  const [legacyCapabilities, setCapabilities] = useState<{
    client: ApiClient;
    value: ExplanationCapabilities;
  } | null>(null);
  const [groundedCapabilities, setGroundedCapabilities] = useState<{
    client: ApiClient;
    value: GroundedExplanationCapabilities;
  } | null>(null);
  const capabilities =
    legacyCapabilities?.client === client ? legacyCapabilities.value : null;
  const groundedConfigured =
    groundedCapabilities?.client === client &&
    groundedCapabilities.value.grounded_explanation === "configured";
  const [mode, setMode] = useState<"legacy" | "grounded">("legacy");
  const [semantic, setSemantic] = useState(false);
  const [, redraw] = useReducer((n: number) => n + 1, 0);
  const gateRef = useRef<ExplanationRequestGate | null>(null);
  if (!gateRef.current) gateRef.current = new ExplanationRequestGate();
  const gate = gateRef.current;
  const scope: ExplanationRequestScope = {
    client,
    analysis,
    finding,
    snapshot: snapshot ?? null,
    mode,
    retrieval: semantic ? "semantic_supplement" : "explicit_reference",
  };
  gate.bind(scope);
  const { loading, permission } = gate;
  const bundle =
    receivedBundle && sameExplanationScope(receivedBundle.scope, scope)
      ? receivedBundle.value
      : null;
  const grounded =
    bundle?.version === "grounded-model-explanation-0.1.0" ? bundle : null;
  const presentation = grounded
    ? groundedExplanationPresentation(grounded)
    : null;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      gate.invalidate();
    };
  }, [gate]);
  useEffect(() => {
    let alive = true;
    void client
      .explanationCapabilities()
      .then((received) => {
        if (alive) setCapabilities({ client, value: received });
      })
      .catch((problem: unknown) => {
        if (alive && problem instanceof ApiError && problem.status === 401)
          onError(problem);
      });
    void client
      .groundedExplanationCapabilities()
      .then((received) => {
        if (alive) setGroundedCapabilities({ client, value: received });
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
    if (semantic && capabilities?.semantic_retrieval !== "configured") {
      onError(
        new ApiError(
          503,
          "Семантический поиск недоступен. Выберите явные ссылки отдельно.",
        ),
      );
      return;
    }
    if (
      model &&
      (!client.permits("model_explanation") ||
        !permission ||
        (mode === "grounded"
          ? !groundedConfigured || !snapshot
          : capabilities?.local_model !== "configured"))
    )
      return;
    const saved = analysis.explanations.find(
      (item) => item.finding_id === finding.finding_id,
    );
    if (!saved) return;
    const request = gate.begin(model);
    if (request === null) return;
    const current = () => mounted.current && gate.current(request);
    redraw();
    setBundle(null);
    try {
      const options = {
        analysis_id: analysis.analysis_id,
        finding_sha256: saved.finding_sha256,
        retrieval: semantic
          ? ("semantic_supplement" as const)
          : ("explicit_reference" as const),
      };
      const result = model
        ? mode === "grounded"
          ? await client.explainGrounded(finding.finding_id, {
              ...options,
              provider: "llm",
              allow_local_model_context: true,
            })
          : await client.explainModel(finding.finding_id, {
              ...options,
              provider: "llm",
              allow_local_model_context: true,
            })
        : await client.explain(finding.finding_id, {
            ...options,
            provider: "local",
          });
      if (!current()) return;
      if (
        result.retrieval !== options.retrieval ||
        !(result.version === "grounded-model-explanation-0.1.0"
          ? await groundedExplanationMatches(
              result,
              analysis,
              finding,
              snapshot,
            )
          : await explanationMatches(result, analysis, finding))
      )
        throw new ApiError(
          0,
          "Источники или объяснение не соответствуют выбранной находке.",
        );
      if (current()) setBundle({ value: result, scope });
    } catch (problem: unknown) {
      if (current()) onError(problem);
    } finally {
      if (current()) {
        gate.finish(request);
        redraw();
      }
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
      {capabilities?.semantic_retrieval === "configured" && (
        <label>
          <input
            type="checkbox"
            checked={semantic}
            disabled={busy || loading}
            onChange={(event) => setSemantic(event.target.checked)}
          />{" "}
          Дополнить источники локальным семантическим поиском
          <span className="hint">
            {" "}
            — обязательные ссылки сохраняются; модель поиска получает только
            публичное описание правила, без конфигурации. Это не проверка
            истинности.
          </span>
        </label>
      )}
      <button
        className="button secondary"
        disabled={busy || loading}
        onClick={() => void load(false)}
      >
        {loading ? "Загрузка источников…" : "Показать источники объяснения"}
      </button>
      {(capabilities?.local_model === "configured" || groundedConfigured) &&
        client.permits("model_explanation") && (
          <div className="model-explanation-controls">
            <label>
              Режим объяснения модели
              <select
                value={mode}
                disabled={busy}
                onChange={(event) =>
                  setMode(event.target.value as "legacy" | "grounded")
                }
              >
                <option value="legacy">
                  Прежний режим — непроверенный текст
                </option>
                <option value="grounded">
                  Закрытые факты — серверное объяснение
                </option>
              </select>
            </label>
            <p className="hint">
              {mode === "grounded"
                ? "Модель выбирает ссылки на факты и коды. Текст составляет сервер. Это не новая проверка и не доказательство безопасности."
                : "Модель пишет свободный текст, достоверность которого не установлена."}
              {mode === "grounded" &&
                !groundedConfigured &&
                " Закрытый режим не настроен."}
              {mode === "grounded" &&
                !snapshot &&
                " Для сверки фактов требуется связанный снимок конфигурации."}
            </p>
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
                onChange={(event) => {
                  gate.allow(event.target.checked);
                  redraw();
                }}
              />{" "}
              Разрешаю передачу этого контекста локальной модели
            </label>
            <button
              className="button secondary"
              disabled={
                busy ||
                loading ||
                !permission ||
                (mode === "grounded"
                  ? !groundedConfigured || !snapshot
                  : capabilities?.local_model !== "configured")
              }
              onClick={() => void load(true)}
            >
              {mode === "grounded"
                ? "Запросить серверное объяснение фактов"
                : "Запросить черновик у локальной модели"}
            </button>
          </div>
        )}
      {loading && (
        <p role="status">Получение разделов для выбранной находки…</p>
      )}
      {bundle && (
        <>
          <p className="hint">
            {bundle.retrieval === "semantic_supplement"
              ? "Явные ссылки детектора + локальный семантический контекст"
              : "Подбор по явным ссылкам детектора"}{" "}
            · {bundle.knowledge_version}. Источники закреплены за версией
            детектора. Оценки и сохранённое объяснение не изменены.
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
          {grounded && presentation && (
            <div aria-label="Серверное объяснение выбранных фактов">
              <h4>Серверное объяснение — закрытый ответ модели</h4>
              <p className="notice warning">
                Текст сформирован сервером из предоставленных фактов и закрытых
                выборов модели. Требуется проверка инженером. Новая проверка
                детектора, vendor syntax, сетевого влияния, доступа и rollback
                здесь не выполнялась. Оценки и формальные статусы не изменены.
              </p>
              <p>{presentation.summary}</p>
              <pre>{presentation.technical_explanation}</pre>
              <h5>Границы сведений о влиянии</h5>
              <ul>
                {presentation.possible_impact.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
              <h5>Рекомендация для рассмотрения</h5>
              <pre>{presentation.recommendation}</pre>
              <h5>Допущения</h5>
              <ul>
                {presentation.assumptions.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
              <h5>Недостающие сведения</h5>
              <ul>
                {presentation.missing_information.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
              <p className="hint">
                Исполняемый патч не создаётся. Ответ не сохранён как новый
                анализ.
              </p>
              <details>
                <summary>Привязка закрытого ответа и серверного текста</summary>
                <p>
                  {grounded.version} · {grounded.renderer_version}
                </p>
                <p>Настроенный alias: {grounded.model_alias}</p>
                <p className="hash">Контекст: {grounded.context_sha256}</p>
                <p className="hash">Факты: {grounded.facts_binding_sha256}</p>
                <p className="hash">Ответ: {grounded.model_answer_sha256}</p>
                <p className="hash">Текст: {grounded.projection_sha256}</p>
                <p className="hash">
                  Инструкции: {grounded.instructions_sha256}
                </p>
                <p className="hash">Схема: {grounded.answer_schema_sha256}</p>
                <p className="hash">
                  Правила отображения: {grounded.renderer_policy_sha256}
                </p>
                <p>
                  Хеши связывают содержимое; они не подтверждают истинность
                  фактов, личность инженера или веса модели.
                </p>
                <ul>
                  {presentation.citations.map((item) => (
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
              {bundle.semantic_retrieval && (
                <p className="hint">
                  {bundle.semantic_retrieval.required_citations.includes(
                    chunk.citation,
                  )
                    ? "Обязательный источник детектора."
                    : `Дополнительный контекст · cosine ${bundle.semantic_retrieval.matches
                        .find((item) => item.citation === chunk.citation)
                        ?.cosine_similarity.toFixed(
                          3,
                        )} · не confidence детектора.`}
                </p>
              )}
              <pre className="knowledge-content">{chunk.content}</pre>
              <p className="hash">SHA-256 документа: {chunk.document_sha256}</p>
              <p className="hash">SHA-256 раздела: {chunk.content_sha256}</p>
            </details>
          ))}
          <details>
            <summary>Привязка источников и ограничения</summary>
            <p className="hash">Каталог: {bundle.knowledge_sha256}</p>
            <p className="hash">Находка: {bundle.finding_sha256}</p>
            {bundle.semantic_retrieval && (
              <>
                <p>
                  Document encoder: {bundle.semantic_retrieval.encoder.model_id}
                </p>
                <p className="hash">
                  Индекс: {bundle.semantic_retrieval.index_sha256}
                </p>
                <p className="hash">
                  Публичный query: {bundle.semantic_retrieval.query_sha256}
                </p>
                <p>{bundle.semantic_retrieval.encoder.pipeline_version}</p>
              </>
            )}
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
