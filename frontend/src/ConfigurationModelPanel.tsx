import { useEffect, useRef, useState } from "react";
import type { ApiClient } from "./api";
import type { AnalysisResult } from "./contracts";
import type {
  ConfigurationModelCapabilities,
  ConfigurationModelRun,
  RunConfigurationModel,
} from "./configurationModels";
import { configurationRunAnalysisMatches } from "./configurationModels";
import { numericScore, date } from "./format";

export function ConfigurationModelPanel({
  client,
  analysis,
}: {
  client: ApiClient;
  analysis: AnalysisResult;
}) {
  const [capabilities, setCapabilities] =
    useState<ConfigurationModelCapabilities | null>(null);
  const [rows, setRows] = useState<ConfigurationModelRun[]>([]);
  const [consent, setConsent] = useState(false);
  const [intent, setIntent] = useState<RunConfigurationModel | null>(null);
  const [result, setResult] = useState<ConfigurationModelRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    Promise.all([
      client.configurationModelCapabilities(),
      client.configurationModelRuns(analysis.analysis_id),
    ])
      .then(([caps, history]) => {
        if (!alive.current) return;
        if (
          history.some((row) => !configurationRunAnalysisMatches(row, analysis))
        )
          throw new Error("Привязка истории к анализу не подтверждена.");
        setCapabilities(caps);
        setRows(history);
      })
      .catch(() => {
        if (alive.current)
          setProblem(
            "История конфигурационной модели недоступна. Обновите анализ; запуск не выполнялся.",
          );
      });
    return () => {
      alive.current = false;
    };
  }, [client, analysis]);
  function accept(row: ConfigurationModelRun) {
    if (!configurationRunAnalysisMatches(row, analysis))
      throw new Error("Привязка результата к анализу не подтверждена.");
    setResult(row);
    setRows((previous) =>
      [
        row,
        ...previous.filter((item) => item.inference_id !== row.inference_id),
      ].slice(0, 20),
    );
  }
  async function run() {
    if (
      busy ||
      intent ||
      !consent ||
      !capabilities?.model_sha256 ||
      !client.permits("configuration_model")
    )
      return;
    const request: RunConfigurationModel = {
      inference_id: crypto.randomUUID(),
      analysis_id: analysis.analysis_id,
      source_sha256: analysis.source_sha256,
      model_sha256: capabilities.model_sha256,
      allow_local_model_context: true,
    };
    setIntent(request);
    setBusy(true);
    setProblem("");
    setConsent(false);
    try {
      const row = await client.runConfigurationModel(request);
      if (alive.current) accept(row);
    } catch {
      if (alive.current)
        setProblem(
          "Итог запроса не подтверждён. Проверьте сохранённый UUID: повторного POST не будет.",
        );
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function reconcile() {
    if (!intent || busy) return;
    setBusy(true);
    setProblem("");
    try {
      const row = await client.configurationModelRun(
        intent.inference_id,
        intent,
      );
      if (alive.current) accept(row);
    } catch {
      if (alive.current)
        setProblem(
          "Запись не получена. Отсутствие ответа не доказывает отсутствие запуска; POST не повторён.",
        );
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  const prediction = result?.report?.prediction;
  return (
    <section className="panel" aria-label="Конфигурационная модель">
      <h3>Экспериментальная конфигурационная модель</h3>
      <p className="notice warning">
        Некалиброванные scores не являются вероятностью ошибки, severity находки
        или доказательством безопасности. Они не меняют итоговый риск. Качество
        модели независимо не подтверждено.
      </p>
      <p className="hint">
        Нужен заранее сохранённый оригинал и полный разбор. Модель выбирает
        оператор; исходник обезличивается перед inference. Восстановление текста
        из IR, обучение и применение патчей не выполняются.
      </p>
      {capabilities && (
        <p>
          {capabilities.inference === "configured"
            ? "Модель настроена; её работоспособность этим не проверена."
            : "Конфигурационная модель отключена."}
        </p>
      )}
      {capabilities?.model_sha256 && (
        <dl className="identifiers">
          <dt>Model SHA-256</dt>
          <dd>{capabilities.model_sha256}</dd>
        </dl>
      )}
      {problem && (
        <p role="status" className="notice warning">
          {problem}
        </p>
      )}
      {client.permits("configuration_model") &&
        capabilities?.inference === "configured" &&
        analysis.status !== "partial" &&
        !intent && (
          <>
            <label>
              <input
                type="checkbox"
                checked={consent}
                disabled={busy}
                onChange={(event) => setConsent(event.target.checked)}
              />
              Разрешаю отдельный локальный inference сохранённого оригинала
            </label>
            <button
              type="button"
              disabled={!consent || busy}
              onClick={() => void run()}
            >
              Запустить конфигурационную модель
            </button>
          </>
        )}
      {analysis.status === "partial" && (
        <p>Запуск недоступен при неполном разборе.</p>
      )}
      {intent && (
        <>
          <dl className="identifiers">
            <dt>UUID попытки</dt>
            <dd>{intent.inference_id}</dd>
          </dl>
          <button
            type="button"
            disabled={busy}
            onClick={() => void reconcile()}
          >
            Проверить сохранённую попытку
          </button>
          <button
            type="button"
            disabled={busy || result?.status === "pending"}
            onClick={() => {
              setIntent(null);
              setResult(null);
              setConsent(false);
              setProblem("");
            }}
          >
            Новая попытка с новым согласием
          </button>
        </>
      )}
      {busy && <p role="status">Ожидание результата модели…</p>}
      {result && (
        <div>
          <h4>Сохранённый результат: {result.status}</h4>
          {result.status === "pending" && (
            <p>
              Зарезервирована одна попытка. Наличие работающего процесса не
              подтверждено; автоматического повтора нет.
            </p>
          )}
          {result.status === "failed" && (
            <p>Попытка завершилась отказом. Принятых scores нет.</p>
          )}
          {prediction && (
            <>
              <p>
                Некалиброванный anomaly score:{" "}
                {prediction.anomaly_score === null
                  ? "голова отключена"
                  : numericScore(prediction.anomaly_score)}
              </p>
              <details>
                <summary>Категории, строки и метаданные модели</summary>
                <p>
                  Классы описывают target semantics:{" "}
                  {result.report?.model.target_semantics}. Severity distribution
                  не равна уровню ущерба. Attention не является причинным
                  объяснением. Embedding сохранён только как hash и размерность.
                </p>
                <pre className="json-view">
                  {JSON.stringify(result.report, null, 2)}
                </pre>
              </details>
            </>
          )}
        </div>
      )}
      <details>
        <summary>
          История конфигурационной модели ({rows.length}; до 20 последних)
        </summary>
        <p>Чтение не запускает модель и не пересчитывает старый анализ.</p>
        {rows.map((row) => (
          <button
            type="button"
            key={row.inference_id}
            disabled={busy}
            onClick={() => {
              setResult(row);
              setIntent(null);
              setConsent(false);
            }}
          >
            {date(row.created_at)} · {row.status} · {row.inference_id}
          </button>
        ))}
      </details>
    </section>
  );
}
