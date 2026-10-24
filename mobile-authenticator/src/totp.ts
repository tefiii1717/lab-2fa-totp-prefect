/**
 * TOTP (RFC 6238) desde cero: Base32 -> HMAC-SHA1 -> truncamiento dinámico.
 *
 * No depende de ninguna librería (ni de red): SHA-1, HMAC y Base32 están
 * implementados aquí mismo, así que funciona en modo avión.
 */

export const DIGITS = 6;
export const PERIOD = 30;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bitsInBuffer = 0;

  for (const char of clean) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Carácter Base32 inválido: "${char}"`);
    }
    // Cada carácter aporta 5 bits; cuando hay 8 o más, sale un byte.
    buffer = (buffer << 5) | value;
    bitsInBuffer += 5;
    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes.push((buffer >>> bitsInBuffer) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

export function isValidBase32Secret(input: string): boolean {
  try {
    return base32Decode(input).length >= 10; // mínimo 80 bits
  } catch {
    return false;
  }
}

function rotl(value: number, bits: number): number {
  return (value << bits) | (value >>> (32 - bits));
}

/** SHA-1 (FIPS 180-4). Devuelve 20 bytes. */
export function sha1(message: Uint8Array): Uint8Array {
  const bitLength = message.length * 8;
  // Padding: 0x80, ceros, y la longitud en bits como entero de 64 bits big-endian.
  const paddedLength = (((message.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(message);
  padded[message.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(paddedLength - 4, bitLength >>> 0);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);

  for (let block = 0; block < paddedLength; block += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(block + i * 4);
    }
    for (let i = 16; i < 80; i++) {
      w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f: number;
      let k: number;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30) >>> 0;
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((h, i) => outView.setUint32(i * 4, h));
  return out;
}

/** HMAC (RFC 2104) con SHA-1, bloque de 64 bytes. */
export function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  const k = key.length > blockSize ? sha1(key) : key;
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(k);

  const inner = new Uint8Array(blockSize + message.length);
  const outer = new Uint8Array(blockSize + 20);
  for (let i = 0; i < blockSize; i++) {
    inner[i] = paddedKey[i] ^ 0x36;
    outer[i] = paddedKey[i] ^ 0x5c;
  }
  inner.set(message, blockSize);
  outer.set(sha1(inner), blockSize);
  return sha1(outer);
}

/** HOTP (RFC 4226) para un contador dado. */
export function hotp(key: Uint8Array, counter: number, digits = DIGITS): string {
  // Contador como entero de 8 bytes big-endian.
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const digest = hmacSha1(key, counterBytes);

  // Truncamiento dinámico.
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];

  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

export function timeStep(unixMillis = Date.now(), period = PERIOD): number {
  return Math.floor(unixMillis / 1000 / period);
}

export function secondsRemaining(unixMillis = Date.now(), period = PERIOD): number {
  return period - (Math.floor(unixMillis / 1000) % period);
}

export function totp(secretBase32: string, unixMillis = Date.now(), digits = DIGITS): string {
  return hotp(base32Decode(secretBase32), timeStep(unixMillis), digits);
}

export interface OtpAuthAccount {
  secret: string;
  issuer: string;
  account: string;
}

/** Extrae secret/issuer/cuenta de otpauth://totp/Issuer:cuenta?secret=...&issuer=... */
export function parseOtpAuthUri(uri: string): OtpAuthAccount {
  const match = /^otpauth:\/\/totp\/([^?]*)\?(.*)$/i.exec(uri.trim());
  if (!match) {
    throw new Error('El QR no es una URI otpauth://totp/');
  }
  const label = decodeURIComponent(match[1]);
  const params: Record<string, string> = {};
  for (const pair of match[2].split('&')) {
    const [rawKey, rawValue = ''] = pair.split('=');
    params[decodeURIComponent(rawKey).toLowerCase()] = decodeURIComponent(rawValue.replace(/\+/g, ' '));
  }

  const secret = params.secret;
  if (!secret || !isValidBase32Secret(secret)) {
    throw new Error('La URI no trae un parámetro secret Base32 válido');
  }
  if ((params.algorithm ?? 'SHA1').toUpperCase() !== 'SHA1') {
    throw new Error('Solo se soporta algorithm=SHA1');
  }

  const [labelIssuer, ...rest] = label.includes(':') ? label.split(':') : ['', label];
  return {
    secret: secret.toUpperCase(),
    issuer: params.issuer ?? labelIssuer,
    account: (rest.join(':') || label).trim(),
  };
}
