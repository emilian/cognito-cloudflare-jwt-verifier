function base64UrlToBinary(input: string) {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  return atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '='));
}

function base64UrlToJson(input: string) {
  const binary = base64UrlToBinary(input);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

export default function decode(token: string) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT must have 3 parts');
  const header = base64UrlToJson(parts[0]);
  const payload = base64UrlToJson(parts[1]);
  const signature = base64UrlToBinary(parts[2]);
  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: { header: parts[0], payload: parts[1], signature: parts[2] },
  };
}
