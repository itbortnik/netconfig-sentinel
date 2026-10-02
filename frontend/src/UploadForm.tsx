import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { Upload } from "./contracts";
import { readConfigurationFile, validateUpload } from "./upload";

type Props = {
  device: string;
  onDevice: (id: string) => void;
  busy: boolean;
  onUpload: (upload: Upload) => Promise<boolean>;
};

export function UploadForm({ device, onDevice, busy, onUpload }: Props) {
  const [filename, setFilename] = useState("configuration.cfg");
  const [content, setContent] = useState("");
  const [role, setRole] = useState("");
  const [siteClass, setSiteClass] = useState("");
  const [profile, setProfile] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  const revision = useRef(0);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      revision.current += 1;
    };
  }, []);
  async function chooseFile(file: File | undefined) {
    if (!file) return;
    const selected = ++revision.current;
    setReading(true);
    setError(null);
    try {
      const text = await readConfigurationFile(file);
      if (alive.current && selected === revision.current) {
        setFilename(file.name);
        setContent(text);
      }
    } catch (failure) {
      if (alive.current && selected === revision.current)
        setError(
          failure instanceof Error ? failure.message : "Файл не прочитан.",
        );
    } finally {
      if (alive.current && selected === revision.current) setReading(false);
    }
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    const upload: Upload = {
      device_id: device,
      filename,
      content,
      ...(role || siteClass || profile
        ? {
            inventory: {
              device_role: role,
              site_class: siteClass,
              service_profile: profile,
            },
          }
        : {}),
    };
    const invalid = validateUpload(upload);
    setError(invalid);
    if (invalid) return;
    if ((await onUpload(upload)) && alive.current) {
      setContent("");
      if (fileInput.current) fileInput.current.value = "";
    }
  }
  const disabled = busy || reading;
  return (
    <section className="panel upload-panel" aria-labelledby="upload-heading">
      <div className="section-heading">
        <span className="eyebrow">01 / ПРИЁМ КОНФИГУРАЦИИ</span>
        <h2 id="upload-heading">Новый снимок</h2>
      </div>
      <form
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <label htmlFor="device-id">UUID устройства</label>
        <div className="input-action">
          <input
            id="device-id"
            value={device}
            onChange={(event) => onDevice(event.target.value)}
            disabled={disabled}
            spellCheck={false}
            autoComplete="off"
            required
          />
          <button
            type="button"
            className="button secondary compact"
            onClick={() => onDevice(crypto.randomUUID())}
            disabled={disabled}
          >
            Новое
          </button>
        </div>
        <p className="hint">
          Для следующей версии используйте UUID того же устройства.
        </p>
        <details>
          <summary>Метки группы сравнения (необязательно)</summary>
          <p className="hint">
            Для peer-сравнения заполните все три поля. Метки задаёт оператор;
            они сохраняются со снимком и не выводятся из конфигурации
            автоматически.
          </p>
          <label htmlFor="inventory-role">Роль устройства</label>
          <input
            id="inventory-role"
            value={role}
            onChange={(event) => setRole(event.target.value)}
            disabled={disabled}
            maxLength={64}
            autoComplete="off"
          />
          <label htmlFor="inventory-site">Класс площадки</label>
          <input
            id="inventory-site"
            value={siteClass}
            onChange={(event) => setSiteClass(event.target.value)}
            disabled={disabled}
            maxLength={64}
            autoComplete="off"
          />
          <label htmlFor="inventory-profile">Профиль сервиса</label>
          <input
            id="inventory-profile"
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
            disabled={disabled}
            maxLength={64}
            autoComplete="off"
          />
        </details>
        <label className="file-picker" htmlFor="config-file">
          <span>Выбрать конфигурацию</span>
          <small>.cfg / .conf / .txt · UTF-8 · до 2 MiB</small>
        </label>
        <input
          ref={fileInput}
          id="config-file"
          type="file"
          accept=".cfg,.conf,.txt"
          onChange={(event) => {
            void chooseFile(event.target.files?.[0]);
          }}
          disabled={disabled}
        />
        <label htmlFor="filename">Имя файла</label>
        <input
          id="filename"
          value={filename}
          onChange={(event) => setFilename(event.target.value)}
          disabled={disabled}
          maxLength={255}
          autoComplete="off"
          required
        />
        <label htmlFor="configuration-text">Текст конфигурации</label>
        <textarea
          id="configuration-text"
          value={content}
          onChange={(event) => setContent(event.target.value)}
          disabled={disabled}
          rows={8}
          placeholder={"hostname edge-01\n…"}
          spellCheck={false}
          autoComplete="off"
          required
        />
        {error && (
          <p className="inline-error" role="alert">
            {error}
          </p>
        )}
        <button
          className="button primary full"
          disabled={disabled}
          type="submit"
        >
          {reading
            ? "Чтение файла…"
            : busy
              ? "Операция выполняется…"
              : "Сохранить снимок"}
        </button>
        <p className="hint">
          Файл передаётся только этому API. Внешние сервисы не вызываются.
        </p>
      </form>
    </section>
  );
}
