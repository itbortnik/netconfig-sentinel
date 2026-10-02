import { inventorySchema } from "./contracts";
import type { Upload } from "./contracts";

export const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const encoder = new TextEncoder();

export function validateUpload(upload: Upload): string | null {
  if (upload.inventory && !inventorySchema.safeParse(upload.inventory).success)
    return "Заполните все три метки группы: 1–64 символа без крайних пробелов и управляющих символов.";
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(upload.device_id))
    return "Введите UUID устройства или создайте новый.";
  if (
    !upload.filename ||
    upload.filename.length > 255 ||
    /[\\/:\x00-\x1f]/.test(upload.filename) ||
    !/\.(cfg|conf|txt)$/i.test(upload.filename)
  )
    return "Нужно имя файла без пути с расширением .cfg, .conf или .txt.";
  if (!upload.content.trim()) return "Добавьте текст конфигурации.";
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(upload.content))
    return "В тексте есть недопустимые управляющие символы.";
  if (encoder.encode(upload.content).byteLength > MAX_TEXT_BYTES)
    return "Конфигурация должна быть не больше 2 MiB UTF-8.";
  if (
    upload.content.split(/\r\n|[\r\n\u0085\u2028\u2029]/).length -
      Number(/[\r\n\u0085\u2028\u2029]$/.test(upload.content)) >
    10_000
  )
    return "Допускается не больше 10 000 строк.";
  if (encoder.encode(JSON.stringify(upload)).byteLength > 3 * 1024 * 1024)
    return "JSON-запрос превышает 3 MiB. Уменьшите конфигурацию.";
  return null;
}

export async function readConfigurationFile(file: File): Promise<string> {
  if (!/\.(cfg|conf|txt)$/i.test(file.name))
    throw new Error("Выберите файл .cfg, .conf или .txt.");
  if (file.size > MAX_TEXT_BYTES)
    throw new Error("Файл должен быть не больше 2 MiB.");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(
      await file.arrayBuffer(),
    );
  } catch {
    throw new Error("Не удалось прочитать файл как UTF-8.");
  }
}
