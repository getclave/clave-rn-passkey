import { Buffer } from 'buffer';

export const fromBase64Url = (text: string) => {
  return Buffer.from(text, 'base64').toString('hex');
};

export const toBase64Url = (hex: string) => {
  return Buffer.from(hex, 'hex').toString('base64url');
};

/** Removes 0x from hex */
export const parseHex = (hex: string): string => {
  if (hex.startsWith('0x')) {
    return hex.slice(2);
  }
  return hex;
};

/** Converts hex to buffer */
export const hexToBuffer = (hex: string): Buffer => {
  return Buffer.from(parseHex(hex), 'hex');
};

/**
 * Converts DER signature to R and S
 * R and S are hex strings
 */
export const derToRs = (derSignature: string): { r: string; s: string } => {
  /*
    DER signature format:
    0x30 <length total> 0x02 <length r> <r> 0x02 <length s> <s>
  */
  const derBuffer = hexToBuffer(derSignature);

  const rLen = derBuffer[3]!;
  const rOffset = 4;
  const rBuffer = derBuffer.slice(rOffset, rOffset + rLen);
  const sLen = derBuffer[5 + rLen]!;
  const sOffset = 6 + rLen;
  const sBuffer = derBuffer.slice(sOffset, sOffset + sLen);

  const r = rBuffer.toString('hex');
  const s = sBuffer.toString('hex');
  return { r, s };
};
