import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ApiClient } from "../../../src/api";
import { patchDraftSchema } from "../../../src/patches";
import { SourceDeterministicRecheckPanel } from "../../../src/SourceDeterministicRecheckPanel";
import { SourceEvidenceReportPanel } from "../../../src/SourceEvidenceReportPanel";
import controls from "../../../src/testdata/sourcePartialDiagnosticControls.json";
import "../../../src/styles.css";

function Fixture() {
  const index = Number(new URLSearchParams(location.search).get("case") ?? "0");
  const [client, setClient] = useState<ApiClient | null>(null),
    [problem, setProblem] = useState("");
  const draft = patchDraftSchema.parse(controls.cases[index]!.draft);
  useEffect(() => {
    const next = new ApiClient(
      "authored-browser-partial-diagnostic-fixture-token",
    );
    void next.access().then(() => setClient(next));
    return () => next.close();
  }, []);
  return (
    <main>
      <h1>Authored partial diagnostic component fixture</h1>
      <p>
        Контролируемые ответы API для браузерной проверки. Это не выполнение
        HTTP workflow на сервере, политики или движка.
      </p>
      {problem && <p role="alert">{problem}</p>}
      {client && (
        <>
          <SourceDeterministicRecheckPanel
            client={client}
            draft={draft}
            busy={false}
            onError={(e) =>
              setProblem(e instanceof Error ? e.message : "Ошибка")
            }
          />
          <SourceEvidenceReportPanel
            client={client}
            draft={draft}
            busy={false}
            onError={(e) =>
              setProblem(e instanceof Error ? e.message : "Ошибка")
            }
          />
        </>
      )}
    </main>
  );
}
createRoot(document.getElementById("root")!).render(<Fixture />);
