/**
 * Strictly parse the runtime `current_time` value used by conditions.
 *
 * The runtime context accepts RFC 3339 date-times and retains the evaluator's
 * established zoneless form, which is interpreted as UTC. JavaScript's Date
 * parser normalizes invalid calendar values, so validate each calendar and
 * offset component before constructing a Date.
 */
const RUNTIME_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/;

/** A valid instant for `RuntimeContext.current_time`, or undefined when invalid. */
export function parseRuntimeTimestamp(value: string): Date | undefined {
  const match = RUNTIME_TIMESTAMP.exec(value);
  if (match == null) return undefined;

  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);

  if (
    year < 1 ||
    month < 1 || month > 12 ||
    day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59
  ) {
    return undefined;
  }

  const offset = value.match(/([+-])(\d{2}):(\d{2})$/);
  if (offset != null && (Number(offset[2]) > 23 || Number(offset[3]) > 59)) {
    return undefined;
  }

  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : `${value}Z`;
  const date = new Date(normalized);
  const utcYear = date.getUTCFullYear();
  return Number.isNaN(date.getTime()) || utcYear < 1 || utcYear > 9999 ? undefined : date;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}
