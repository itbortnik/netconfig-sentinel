import type { IngressScope } from "./ingressScope";

const reasons = {
  query_completed: "Наблюдения обеих сторон получены",
  not_run: "Наблюдение не выполнялось",
  query_failed: "Получить наблюдения не удалось",
  unsupported_answer: "Форма ответа не поддерживается",
  unsupported_location: "Точка входа не поддерживается",
  incomplete_assignment: "Назначения адресов источника неполны",
  budget_exceeded: "Ответ превышает предел сохранения",
  cleanup_unconfirmed: "Очистка исходников на движке не подтверждена",
};
const eligibility = {
  active_concrete_ipv4:
    "Пригоден: активен, не switchport, есть конкретный IPv4",
  inactive: "Не пригоден: неактивен",
  switchport: "Не пригоден: switchport",
  no_concrete_ipv4: "Неизвестно: конкретный IPv4 отсутствует",
};
const count = (rows: unknown[] | null) =>
  rows === null ? "неизвестно" : rows.length;
export function IngressScopeView({ scope }: { scope: IngressScope }) {
  const sets = [
    ["Выбраны только до", scope.selected_before_only],
    ["Выбраны только после", scope.selected_after_only],
    ["Пригодны в обоих снимках", scope.common_eligible],
    ["Пригодны только до", scope.before_eligible_only],
    ["Пригодны только после", scope.after_eligible_only],
  ] as const;
  return (
    <section aria-label="Наблюдаемая область точек входа IPv4">
      <h5>Наблюдаемая область точек входа IPv4</h5>
      <p
        className={
          scope.acquisition_state === "observed" ? undefined : "notice warning"
        }
      >
        {reasons[scope.reason]}. Выбрано интерфейсов до:{" "}
        {count(scope.before?.interfaces ?? null)}; после:{" "}
        {count(scope.after?.interfaces ?? null)}.
      </p>
      <p>
        Пригодность всех выбранных интерфейсов:{" "}
        {scope.eligibility_complete === true
          ? "определена"
          : scope.eligibility_complete === false
            ? "определена не для всех; общие пригодные множества неизвестны"
            : "неизвестно"}
        . Выбор интерфейса не означает пригодность для источника IPv4.
        Активность — свойство модели, а не состояние линии оборудования.
      </p>
      <dl>
        {sets.map(([name, rows]) => (
          <div key={name}>
            <dt>{name}</dt>
            <dd>{count(rows)}</dd>
          </div>
        ))}
      </dl>
      <p className="hint">
        Представления адресов источника сохранены отдельно для каждого снимка.
        Назначения для общих пригодных точек берутся из снимка «после». Смысл
        множеств IP, их равенство и полный охват потоков не проверены. Значение
        «неизвестно» не означает ноль. Удалённые точки входа, вся сеть, доступ
        управления, внешняя доставка, согласование и безопасность этим не
        установлены.
      </p>
      <details>
        <summary>Сохранённые интерфейсы и назначения источника</summary>
        {(["before", "after"] as const).map((side) => (
          <div key={side}>
            <h6>{side === "before" ? "До изменения" : "После изменения"}</h6>
            {scope[side] === null ? (
              <p>Наблюдения недоступны.</p>
            ) : (
              <div className="forest-scores">
                <table
                  aria-label={`Выбранные интерфейсы ${side === "before" ? "до" : "после"}`}
                >
                  <thead>
                    <tr>
                      <th>Узел / интерфейс</th>
                      <th>Наблюдаемая точка и идентификатор</th>
                      <th>Свойства</th>
                      <th>Конкретные IPv4</th>
                      <th>Пригодность</th>
                      <th>Текст источника и SHA-256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scope[side].interfaces.map((row) => (
                      <tr key={row.canonical_id_sha256}>
                        <td>
                          {row.node} / {row.interface}
                        </td>
                        <td>
                          <span>{row.location_rendering}</span>
                          <br />
                          <code>{row.canonical_id_sha256}</code>
                        </td>
                        <td>
                          Активен: {row.active ? "да" : "нет"}; switchport:{" "}
                          {row.switchport ? "да" : "нет"}; тип:{" "}
                          {row.interface_type}
                        </td>
                        <td>
                          {row.concrete_ipv4_prefixes.length
                            ? row.concrete_ipv4_prefixes.join(", ")
                            : "не наблюдались"}
                        </td>
                        <td>{eligibility[row.eligibility_reason]}</td>
                        <td>
                          <pre className="json-view">
                            {row.source_ip_rendering}
                          </pre>
                          <code>{row.source_ip_sha256}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))}
        {sets.map(([name, rows]) => (
          <div key={name}>
            <h6>{name}</h6>
            {rows === null ? (
              <p>Неизвестно.</p>
            ) : (
              <ul>
                {rows.map((id) => (
                  <li key={id}>
                    <code>{id}</code>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
        <h6>Назначения после для общих пригодных идентификаторов</h6>
        {scope.after_common_assignments === null ? (
          <p>Неизвестно.</p>
        ) : (
          <ul>
            {scope.after_common_assignments.map((row) => (
              <li key={row.canonical_id_sha256}>
                <code>{row.canonical_id_sha256}</code>
                <pre className="json-view">{row.source_ip_rendering}</pre>
                <code>{row.source_ip_sha256}</code>
              </li>
            ))}
          </ul>
        )}
        <p className="mono">
          SHA-256 до: {scope.before_sha256}; после: {scope.after_sha256}. Узел:{" "}
          {scope.scope.start_node}; назначение: {scope.scope.destination}. Сеть:{" "}
          {scope.network_name ?? "не наблюдалась"}.
        </p>
      </details>
    </section>
  );
}
