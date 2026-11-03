/** Exempelförmåga: strikt tolkning av portnummer. Mekanism, ingen policy. */
export function striktPort(text: string): number | null {
  if (!/^[1-9][0-9]*$/.test(text)) return null; // ASCII-siffror, ingen nollutfyllnad
  const värde = Number(text);
  return värde >= 1 && värde <= 65535 ? värde : null;
}
