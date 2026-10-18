import type { ConfigurationSnapshot } from "./contracts";

export function RouteMapView({
  routeMaps,
}: {
  routeMaps: NonNullable<ConfigurationSnapshot["canonical"]["route_maps"]>;
}) {
  return (
    <details>
      <summary>Route-map ({routeMaps.length})</summary>
      <p className="hint">
        Настроенные секции в порядке номеров. Применение к маршрутам, ссылки на
        prefix-list и влияние на сеть не проверены.
      </p>
      <div className="fragment-list">
        {routeMaps.map((item) => (
          <div key={item.name}>
            <strong>{item.name}</strong>
            {!item.normalization_complete && (
              <p className="notice warning">Частичный разбор route-map</p>
            )}
            <ol>
              {item.clauses.map((clause) => (
                <li key={clause.sequence}>
                  <p>
                    Номер {clause.sequence} · {clause.action}
                  </p>
                  <p>
                    IPv4 prefix-list:{" "}
                    {clause.match_ipv4_prefix_lists.length
                      ? clause.match_ipv4_prefix_lists.join(", ")
                      : "Нет в поддержанном фрагменте"}
                  </p>
                  <p>
                    Метрика:{" "}
                    {clause.set_metric ?? "Нет подтверждённого значения"}
                  </p>
                  {!clause.normalization_complete && (
                    <p>Секция разобрана частично</p>
                  )}
                  <span className="muted">
                    Строки{" "}
                    {clause.provenance.header?.source_lines.join(", ") ??
                      "не заданы"}
                  </span>
                </li>
              ))}
            </ol>
          </div>
        ))}
      </div>
    </details>
  );
}
