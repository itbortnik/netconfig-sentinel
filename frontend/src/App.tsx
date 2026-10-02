import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiClient, ApiError } from "./api";
import { AnalysisView } from "./AnalysisView";
import type {
  AnalysisResult,
  AnalysisSummary,
  ConfigurationSnapshot,
  ConfigurationSummary,
  Upload,
} from "./contracts";
import { date, percent, shortId } from "./format";
import { SnapshotView } from "./SnapshotView";
import { UploadForm } from "./UploadForm";
import { ComparisonSelection } from "./ComparisonSelection";
import { comparisonOptions, selectedSnapshot } from "./comparison";
import type { SelectedSnapshot } from "./comparison";

function Login({
  busy,
  onConnect,
}: {
  busy: boolean;
  onConnect: (token: string) => Promise<void>;
}) {
  const [token, setToken] = useState("");
  function submit(event: FormEvent) {
    event.preventDefault();
    const current = token;
    setToken("");
    void onConnect(current);
  }
  return (
    <section className="panel login-panel">
      <span className="eyebrow">ДОСТУП К ЛОКАЛЬНОМУ API</span>
      <h2>Подключить рабочую сессию</h2>
      <p>
        Используйте настроенный service-токен. Его владелец имеет доступ ко всей
        истории.
      </p>
      <form onSubmit={submit}>
        <label htmlFor="api-token">API-токен</label>
        <input
          id="api-token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={token}
          onChange={(event) => setToken(event.target.value)}
          required
          disabled={busy}
        />
        <button type="submit" className="button primary" disabled={busy}>
          {busy ? "Подключение…" : "Подключиться"}
        </button>
      </form>
      <p className="hint">
        Токен не сохраняется в браузерное хранилище и очищается при выходе или
        перезагрузке страницы. Для работы нужны настроенная БД и миграции.
      </p>
    </section>
  );
}

function Pager({
  offset,
  count,
  busy,
  onOffset,
}: {
  offset: number;
  count: number;
  busy: boolean;
  onOffset: (value: number) => void;
}) {
  return (
    <div className="pager">
      <button
        className="button secondary compact"
        disabled={busy || offset === 0}
        onClick={() => onOffset(Math.max(0, offset - 20))}
      >
        Назад
      </button>
      <span className="hint">
        {count ? `${offset + 1}–${offset + count}` : "Нет записей"}
      </span>
      <button
        className="button secondary compact"
        disabled={busy || count < 20 || offset >= 10_000}
        onClick={() => onOffset(offset + 20)}
      >
        Далее
      </button>
    </div>
  );
}

export function App() {
  const [session, setSession] = useState<ApiClient | null>(null);
  const [sessionEpoch, setSessionEpoch] = useState(0);
  const active = useRef<ApiClient | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"configurations" | "analyses">(
    "configurations",
  );
  const [device, setDevice] = useState<string>(() => crypto.randomUUID());
  const [configurations, setConfigurations] = useState<ConfigurationSummary[]>(
    [],
  );
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [configOffset, setConfigOffset] = useState(0);
  const [analysisOffset, setAnalysisOffset] = useState(0);
  const [deviceOnly, setDeviceOnly] = useState(false);
  const [snapshotOnly, setSnapshotOnly] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [snapshot, setSnapshot] = useState<ConfigurationSnapshot | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [reference, setReference] = useState<SelectedSnapshot | null>(null);
  const [peers, setPeers] = useState<SelectedSnapshot[]>([]);

  const disconnect = useCallback(() => {
    active.current?.close();
    active.current = null;
    setSession(null);
    setBusy(false);
    setLoading(false);
    setError(null);
    setSessionEpoch((value) => value + 1);
    setConfigurations([]);
    setAnalyses([]);
    setSnapshot(null);
    setResult(null);
    setReference(null);
    setPeers([]);
    setConfigOffset(0);
    setAnalysisOffset(0);
    setDeviceOnly(false);
    setSnapshotOnly(false);
    setDevice(crypto.randomUUID());
  }, []);
  const failure = useCallback(
    (problem: unknown) => {
      if (problem instanceof DOMException && problem.name === "AbortError")
        return;
      if (problem instanceof ApiError && problem.status === 401) disconnect();
      setError(
        problem instanceof ApiError
          ? problem.message
          : "Операция не выполнена. Обновите историю перед повтором.",
      );
    },
    [disconnect],
  );
  useEffect(() => {
    const restored = (event: PageTransitionEvent) => {
      if (event.persisted) disconnect();
    };
    window.addEventListener("pagehide", disconnect);
    window.addEventListener("pageshow", restored);
    return () => {
      window.removeEventListener("pagehide", disconnect);
      window.removeEventListener("pageshow", restored);
      active.current?.close();
      active.current = null;
    };
  }, [disconnect]);

  async function connect(token: string) {
    setBusy(true);
    setError(null);
    let candidate: ApiClient | null = null;
    try {
      candidate = new ApiClient(token);
      active.current = candidate;
      await candidate.configurations();
      if (active.current === candidate) setSession(candidate);
    } catch (problem) {
      if (candidate === null || active.current === candidate) {
        candidate?.close();
        active.current = null;
        failure(problem);
      }
    } finally {
      if (active.current === candidate || active.current === null)
        setBusy(false);
    }
  }

  const filterDevice = deviceOnly ? snapshot?.device_id : undefined;
  const filterSnapshot = snapshotOnly ? snapshot?.configuration_id : undefined;
  useEffect(() => {
    if (!session) return;
    let alive = true;
    setLoading(true);
    setConfigurations([]);
    setAnalyses([]);
    void Promise.all([
      session.configurations(configOffset, filterDevice),
      session.analyses(analysisOffset, filterSnapshot),
    ])
      .then(([configs, runs]) => {
        if (alive && active.current === session) {
          setConfigurations(configs);
          setAnalyses(runs);
        }
      })
      .catch((problem: unknown) => {
        if (alive && active.current === session) failure(problem);
      })
      .finally(() => {
        if (alive && active.current === session) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [
    session,
    configOffset,
    analysisOffset,
    filterDevice,
    filterSnapshot,
    refresh,
    failure,
  ]);

  async function operation(work: (client: ApiClient) => Promise<void>) {
    const client = active.current;
    if (!client || busy) return false;
    setBusy(true);
    setError(null);
    try {
      await work(client);
      return active.current === client;
    } catch (problem) {
      if (active.current === client) failure(problem);
      return false;
    } finally {
      if (active.current === client) setBusy(false);
    }
  }
  async function upload(body: Upload) {
    return operation(async (client) => {
      const created = await client.upload(body);
      if (active.current !== client) return;
      setSnapshot(created);
      setResult(null);
      setTab("configurations");
      setConfigOffset(0);
      setRefresh((value) => value + 1);
    });
  }
  function openSnapshot(id: string) {
    setSnapshot(null);
    setResult(null);
    void operation(async (client) => {
      const selected = await client.configuration(id);
      if (active.current === client) setSnapshot(selected);
    });
  }
  function bound(analysis: AnalysisResult, config: ConfigurationSnapshot) {
    if (
      analysis.configuration_id !== config.configuration_id ||
      analysis.device_id !== config.device_id ||
      analysis.source_sha256 !== config.canonical.source.sha256
    )
      throw new ApiError(
        0,
        "Результат анализа не соответствует выбранному снимку.",
      );
  }
  function openAnalysis(id: string) {
    setSnapshot(null);
    setResult(null);
    void operation(async (client) => {
      const analysis = await client.analysis(id);
      const config = await client.configuration(analysis.configuration_id);
      bound(analysis, config);
      if (active.current === client) {
        setSnapshot(config);
        setResult(analysis);
      }
    });
  }
  function analyze() {
    if (!snapshot) return;
    const selected = snapshot;
    setResult(null);
    void operation(async (client) => {
      let options;
      try {
        options = comparisonOptions(
          selectedSnapshot(selected),
          reference,
          peers,
        );
      } catch (problem) {
        throw new ApiError(
          400,
          problem instanceof Error
            ? problem.message
            : "Неверный выбор сравнений.",
        );
      }
      const analysis = await client.analyze(selected.configuration_id, options);
      bound(analysis, selected);
      if (active.current !== client) return;
      setResult(analysis);
      setAnalysisOffset(0);
      setRefresh((value) => value + 1);
    });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/ui/" aria-label="NetConfig Sentinel">
          <span className="brand-mark">N</span>
          <span>
            NETCONFIG<small>SENTINEL</small>
          </span>
        </a>
        <span className="nav-label">РАБОЧЕЕ ПРОСТРАНСТВО</span>
        <nav aria-label="Основная навигация">
          <button
            className={tab === "configurations" ? "active" : ""}
            onClick={() => setTab("configurations")}
          >
            Конфигурации
          </button>
          <button
            className={tab === "analyses" ? "active" : ""}
            onClick={() => setTab("analyses")}
          >
            Анализы
          </button>
        </nav>
        <div className="sidebar-bottom">
          <strong>Cisco IOS / JunOS</strong>
          <p>Политики и явные сравнения</p>
          <span className="sidebar-note">Изменения не применяются</span>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">КОНТРОЛЬ КОНФИГУРАЦИЙ</span>
            <h1>
              {tab === "configurations"
                ? "Конфигурации сети"
                : "История анализов"}
            </h1>
          </div>
          <div className="session-controls">
            <span className={`session-label ${session ? "connected" : ""}`}>
              {session ? "Сессия подключена" : "Нет подключения"}
            </span>
            {session && (
              <button className="button secondary compact" onClick={disconnect}>
                Отключиться
              </button>
            )}
          </div>
        </header>
        {error && (
          <div className="notice error" role="alert">
            {error}
          </div>
        )}
        {!session ? (
          <>
            <Login key={sessionEpoch} busy={busy} onConnect={connect} />
            <section className="login-context">
              <h3>Работа с конфигурациями</h3>
              <ol>
                <li>Загрузите снимок Cisco IOS или JunOS.</li>
                <li>Запустите политики и изучите доказательства.</li>
                <li>Сопоставьте вывод с ограничениями парсера.</li>
              </ol>
              <p>
                Неподдержанные команды сохраняются. Наличие результата не
                означает, что сеть формально проверена.
              </p>
            </section>
          </>
        ) : (
          <>
            <div
              className={
                tab === "configurations" ? "intake-grid" : "history-grid"
              }
            >
              {tab === "configurations" && (
                <UploadForm
                  device={device}
                  onDevice={setDevice}
                  busy={busy}
                  onUpload={upload}
                />
              )}
              <section
                className="panel history-panel"
                aria-labelledby="history-heading"
              >
                <div className="section-heading split">
                  <div>
                    <span className="eyebrow">ПОСТОЯННАЯ ИСТОРИЯ</span>
                    <h2 id="history-heading">
                      {tab === "configurations"
                        ? "Снимки конфигураций"
                        : "Запуски анализа"}
                    </h2>
                  </div>
                  <button
                    className="button secondary compact"
                    disabled={busy || loading}
                    onClick={() => {
                      setError(null);
                      setRefresh((value) => value + 1);
                    }}
                  >
                    Обновить
                  </button>
                </div>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    disabled={!snapshot || busy || loading}
                    checked={
                      tab === "configurations" ? deviceOnly : snapshotOnly
                    }
                    onChange={(event) => {
                      if (tab === "configurations") {
                        setDeviceOnly(event.target.checked);
                        setConfigOffset(0);
                      } else {
                        setSnapshotOnly(event.target.checked);
                        setAnalysisOffset(0);
                      }
                    }}
                  />
                  {tab === "configurations"
                    ? "Только выбранное устройство"
                    : "Только выбранный снимок"}
                </label>
                {loading ? (
                  <p className="empty" role="status">
                    Загрузка истории…
                  </p>
                ) : tab === "configurations" ? (
                  <div className="history-items">
                    {configurations.map((item) => (
                      <button
                        key={item.configuration_id}
                        className={`history-item ${snapshot?.configuration_id === item.configuration_id ? "selected" : ""}`}
                        disabled={busy}
                        onClick={() => openSnapshot(item.configuration_id)}
                      >
                        <span className="history-title">
                          <strong>{item.hostname ?? "Без hostname"}</strong>
                          <span
                            className={`badge ${item.warning_count || item.unparsed_count || item.parser_confidence < 1 ? "medium" : "neutral"}`}
                          >
                            {percent(item.parser_confidence)}
                          </span>
                        </span>
                        <span>
                          {item.filename} · {item.vendor.toUpperCase()} /{" "}
                          {item.platform}
                        </span>
                        <span className="muted">
                          {date(item.created_at)} · Снимок{" "}
                          {shortId(item.configuration_id)}
                        </span>
                      </button>
                    ))}
                    {configurations.length === 0 && (
                      <p className="empty">
                        Снимков пока нет. Загрузите конфигурацию или измените
                        фильтр.
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="history-items">
                    {analyses.map((item) => (
                      <button
                        key={item.analysis_id}
                        className={`history-item ${result?.analysis_id === item.analysis_id ? "selected" : ""}`}
                        disabled={busy}
                        onClick={() => openAnalysis(item.analysis_id)}
                      >
                        <span className="history-title">
                          <strong>Анализ {shortId(item.analysis_id)}</strong>
                          <span
                            className={`badge ${item.status === "partial" ? "medium" : "neutral"}`}
                          >
                            {item.status === "partial"
                              ? "Частичный"
                              : "Анализ завершён"}
                          </span>
                        </span>
                        <span>
                          Находки: {item.finding_count} · Снимок{" "}
                          {shortId(item.configuration_id)}
                        </span>
                        <span className="muted">
                          {date(item.created_at)} ·{" "}
                          {item.policy_catalog_version}
                        </span>
                      </button>
                    ))}
                    {analyses.length === 0 && (
                      <p className="empty">
                        Анализов пока нет. Выберите снимок и запустите анализ.
                      </p>
                    )}
                  </div>
                )}
                <Pager
                  offset={
                    tab === "configurations" ? configOffset : analysisOffset
                  }
                  count={
                    tab === "configurations"
                      ? configurations.length
                      : analyses.length
                  }
                  busy={busy || loading}
                  onOffset={
                    tab === "configurations"
                      ? setConfigOffset
                      : setAnalysisOffset
                  }
                />
              </section>
            </div>
            {busy && (
              <p className="operation-status" role="status">
                Операция выполняется. Повторный запуск создаёт новую запись.
              </p>
            )}
            {snapshot && (
              <SnapshotView
                snapshot={snapshot}
                busy={busy}
                onAnalyze={analyze}
                onDevice={() => {
                  setDevice(snapshot.device_id);
                  setTab("configurations");
                }}
                onReference={() => setReference(selectedSnapshot(snapshot))}
                onPeer={() => {
                  const selected = selectedSnapshot(snapshot);
                  if (peers.some((peer) => peer.id === selected.id)) return;
                  if (peers.length >= 20) {
                    setError("Допускается максимум 20 peers.");
                    return;
                  }
                  setPeers((items) => [...items, selected]);
                }}
              />
            )}
            <ComparisonSelection
              reference={reference}
              peers={peers}
              busy={busy}
              onClearReference={() => setReference(null)}
              onRemovePeer={(id) =>
                setPeers((items) => items.filter((peer) => peer.id !== id))
              }
            />
            {result && (
              <AnalysisView key={result.analysis_id} result={result} />
            )}
          </>
        )}
        <footer>
          NetConfig Sentinel · development-срез · политика ≠ полная проверка
          сети
        </footer>
      </main>
    </div>
  );
}
