import type { AnalysisOptions, ModelSummary, TrainModel } from "./contracts";
import type { SelectedSnapshot } from "./comparison";

export function trainingOptions(inputs: SelectedSnapshot[]): TrainModel {
  if (inputs.length < 8 || inputs.length > 100)
    throw new Error("Для обучения выберите 8–100 разных устройств.");
  const group = inputs[0]?.group;
  if (
    !group ||
    inputs.some(
      (item) => !item.complete || !item.hostname || item.group !== group,
    )
  )
    throw new Error(
      "Обучение требует полного разбора, hostname и одной группы по пяти меткам.",
    );
  for (const key of ["id", "device", "hostname", "hash"] as const)
    if (new Set(inputs.map((item) => item[key])).size !== inputs.length)
      throw new Error(
        "Копии и версии одного устройства не считаются независимыми обучающими примерами.",
      );
  return {
    configuration_ids: inputs.map((item) => item.id),
    contamination: 0.1,
  };
}

export function statisticalOptions(
  current: SelectedSnapshot,
  model: ModelSummary,
): AnalysisOptions {
  const group = model.metadata.group;
  if (
    !current.complete ||
    !current.hostname ||
    current.group !==
      JSON.stringify([
        group.vendor,
        group.platform,
        group.device_role,
        group.site_class,
        group.service_profile,
      ])
  )
    throw new Error(
      "Модель требует полного разбора и совпадения группы текущего снимка.",
    );
  if (
    model.training_hostnames.includes(current.hostname) ||
    model.training.some(
      (item) =>
        item.device_id === current.device ||
        item.source_sha256 === current.hash ||
        Date.parse(item.created_at) > Date.parse(current.created),
    )
  )
    throw new Error(
      "Текущий снимок не должен относиться к обучающим устройствам; обучающие снимки не могут быть новее него.",
    );
  return { statistical_model_id: model.model_id };
}
