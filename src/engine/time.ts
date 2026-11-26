const MEDLABS_TIME_ZONE = 'Asia/Amman';

export function formatMedLabsTimestamp(value: Date | number | string = new Date()): string {
  const date = value instanceof Date ? value : new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new Error('Invalid timestamp supplied to formatMedLabsTimestamp.');
  }

  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: MEDLABS_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);

  const part = (type: string) => parts.find((item) => item.type === type)?.value ?? '';

  return `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')}:${part('second')}`;
}