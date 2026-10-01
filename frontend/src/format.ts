import type { Severity } from "./contracts";

export const severityLabel: Record<Severity, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Информация",
};
export const sourceLabel: Record<string, string> = {
  policy: "Политики",
  peer_group: "Группа устройств",
  statistical: "Статистическая модель",
  transformer: "Transformer",
  verification: "Формальная проверка",
};
export const percent = (value: number) =>
  new Intl.NumberFormat("ru-RU", {
    style: "percent",
    maximumFractionDigits: 1,
  }).format(value);
export const numericScore = (value: number) =>
  value.toFixed(3).replace(".", ",");
export const date = (value: string) =>
  new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
export const shortId = (id: string) => id.slice(0, 8);
