// Verifica la implementación contra los vectores oficiales de RFC 6238 (Apéndice B, SHA-1)
// y RFC 4226 (Apéndice D). Ejecutar: npm run verify-totp
import { hotp, parseOtpAuthUri, sha1, totp } from '../src/totp.ts';

// Base32 de la semilla ASCII "12345678901234567890" usada por ambos RFC.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

const totpVectors: [number, string][] = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

const hotpVectors = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

let failures = 0;
function check(label: string, actual: string, expected: string) {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${label}: ${actual}${ok ? '' : ` (esperado ${expected})`}`);
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
check('SHA1("abc")', hex(sha1(new TextEncoder().encode('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
check('SHA1("")', hex(sha1(new Uint8Array())), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');

const key = new TextEncoder().encode('12345678901234567890');
hotpVectors.forEach((expected, counter) => check(`HOTP counter=${counter}`, hotp(key, counter), expected));
totpVectors.forEach(([t, expected]) => check(`TOTP T=${t}`, totp(RFC_SECRET, t * 1000, 8), expected));

const parsed = parseOtpAuthUri(
  'otpauth://totp/LabPatrones2FA%3Aana?secret=JBSWY3DPEHPK3PXP&issuer=LabPatrones2FA&algorithm=SHA1&digits=6&period=30'
);
check('parse otpauth secret', parsed.secret, 'JBSWY3DPEHPK3PXP');
check('parse otpauth account', parsed.account, 'ana');

console.log(failures === 0 ? '\nTodos los vectores coinciden.' : `\n${failures} fallos.`);
process.exit(failures === 0 ? 0 : 1);
