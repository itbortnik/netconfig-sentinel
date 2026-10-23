import {
  reachabilityDirectionNames,
  reachabilityReasonNames,
} from "./sourceReachabilityImpact";
import type { ReachabilityImpact } from "./sourceReachabilityImpact";

export function ReachabilityImpactView({
  impact,
}: {
  impact: ReachabilityImpact;
}) {
  return (
    <section aria-label="Направление примеров достижимости">
      <h5>Примеры изменения успешной доставки</h5>
      <p className={impact.state === "observed" ? undefined : "notice warning"}>
        {impact.direction
          ? reachabilityDirectionNames[impact.direction]
          : "Направление не установлено"}
        . {reachabilityReasonNames[impact.reason]}.
      </p>
      {impact.state === "observed" && (
        <p>
          Примеров потери: {impact.lost_witness_count}; появления:{" "}
          {impact.gained_witness_count}.
        </p>
      )}
      <p className="hint">
        Это примеры IPv4-потоков, а не число пакетов или полный объём
        затронутого трафика. Наблюдение одного направления не исключает другого.
        Появление доставки само по себе не означает улучшения безопасности.
        Отсутствие примеров не доказывает неизменность всей сети.
      </p>
      <p className="hint">
        Учитываются только точки входа, существующие и активные в обоих снимках.
        Адрес источника выводится по снимку после изменения; удалённые точки
        входа не охвачены. Доставка в подсеть или выход из сети не доказывают
        доставку внешнему устройству. Уровень риска, безопасность всей сети,
        доступ управления и согласование этим не устанавливаются.
      </p>
      {impact.witnesses.length > 0 && (
        <div className="forest-scores">
          <table aria-label="Сохранённые примеры изменения доставки">
            <thead>
              <tr>
                <th>Пример потока, SHA-256</th>
                <th>Наблюдение</th>
                <th>Исходы до</th>
                <th>Исходы после</th>
                <th>Полных путей до / после</th>
              </tr>
            </thead>
            <tbody>
              {impact.witnesses.map((row) => (
                <tr key={row.flow_sha256}>
                  <td className="mono">{row.flow_sha256}</td>
                  <td>
                    {row.direction === "loss"
                      ? "Потеря успешной доставки"
                      : "Появление успешной доставки"}
                  </td>
                  <td>{row.before_dispositions.join(", ")}</td>
                  <td>{row.after_dispositions.join(", ")}</td>
                  <td>
                    {row.before_trace_count} / {row.after_trace_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
