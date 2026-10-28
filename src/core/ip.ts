/** Loopback, private, link-local, CGNAT and unique-local ranges never identify the sender. */
export function isPublicIp(ip: string): boolean {
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/u.exec(ip);
  if (v4) {
    const [a = 0, b = 0] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return true;
  }
  const v6 = ip.toLowerCase();
  if (v6 === '::1' || v6 === '::') return false;
  return !/^(?:fc|fd|fe[89ab])/u.test(v6);
}
