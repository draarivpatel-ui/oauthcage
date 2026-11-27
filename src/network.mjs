/* Offline IPv4, IPv6, transition-encoding, and SSRF-sensitive range analysis. */

function numericTokenKind(token) {
  if (/^0[xX][0-9A-Fa-f]+$/u.test(token)) return 'hex';
  if (/^0[0-7]+$/u.test(token) && token.length > 1) return 'octal';
  if (/^[0-9]+$/u.test(token)) return 'decimal';
  return null;
}

function parseNumericToken(token) {
  const kind = numericTokenKind(token);
  if (kind === null) return null;
  if (kind === 'hex') return { value: BigInt('0x' + token.slice(2)), kind };
  if (kind === 'octal') return { value: BigInt(Number.parseInt(token, 8)), kind: 'octal' };
  return { value: BigInt(token), kind: 'decimal' };
}

function integerToIpv4Bytes(integer) {
  return [
    Number((integer >> 24n) & 255n),
    Number((integer >> 16n) & 255n),
    Number((integer >> 8n) & 255n),
    Number(integer & 255n)
  ];
}

export function ipv4BytesToString(bytes) {
  return bytes.join('.');
}

export function parseIpv4Like(text) {
  if (typeof text !== 'string' || text.length === 0 || text.length > 255 || /[\s%]/u.test(text)) return null;
  if (text.endsWith('.')) {
    const beforeDot = text.slice(0, -1).split('.');
    if (beforeDot.some((piece) => numericTokenKind(piece) !== null)) {
      return { valid: false, numericLike: true, obfuscated: true, reason: 'trailing-dot' };
    }
    return null;
  }
  const pieces = text.split('.');
  if (pieces.length < 1 || pieces.length > 4 || pieces.some((piece) => piece.length === 0)) {
    return pieces.some((piece) => numericTokenKind(piece) !== null) ? { valid: false, numericLike: true, obfuscated: true, reason: 'malformed-numeric' } : null;
  }
  const numericKinds = pieces.map(numericTokenKind);
  if (numericKinds.some((kind) => kind === null)) return null;
  const widths = pieces.length === 4 ? [8, 8, 8, 8] : pieces.length === 3 ? [8, 8, 16] : pieces.length === 2 ? [8, 24] : [32];
  let integer = 0n;
  let overflow = false;
  for (let index = 0; index < pieces.length; index += 1) {
    const parsed = parseNumericToken(pieces[index]);
    const maximum = (1n << BigInt(widths[index])) - 1n;
    if (parsed.value > maximum) overflow = true;
    const masked = parsed.value & maximum;
    integer = (integer << BigInt(widths[index])) | masked;
  }
  const strict = pieces.length === 4 && pieces.every((piece, index) => {
    if (!/^[0-9]+$/u.test(piece)) return false;
    if (piece.length > 1 && piece.startsWith('0')) return false;
    return Number(piece) <= 255;
  });
  if (!strict || overflow || pieces.length !== 4) {
    return {
      valid: !overflow,
      numericLike: true,
      obfuscated: true,
      bytes: overflow ? null : integerToIpv4Bytes(integer),
      canonical: overflow ? null : ipv4BytesToString(integerToIpv4Bytes(integer)),
      reason: overflow ? 'overflow' : pieces.length !== 4 ? 'shorthand' : numericKinds.includes('hex') ? 'hex' : numericKinds.includes('octal') || pieces.some((piece) => piece.length > 1 && piece.startsWith('0')) ? 'octal-or-leading-zero' : 'noncanonical'
    };
  }
  const bytes = pieces.map((piece) => Number(piece));
  return { valid: true, numericLike: true, obfuscated: false, bytes, canonical: ipv4BytesToString(bytes), reason: null };
}

export function ipv4Scope(bytes) {
  const [a, b, c, d] = bytes;
  if (a === 169 && b === 254 && c === 169 && d === 254) return 'metadata';
  if (a === 169 && b === 254 && c === 170 && d === 23) return 'metadata';
  if (a === 0) return 'unspecified';
  if (a === 10) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 192 && b === 0 && c === 2) return 'documentation';
  if (a === 198 && (b === 18 || b === 19)) return 'benchmark';
  if (a === 198 && b === 51 && c === 100) return 'documentation';
  if (a === 203 && b === 0 && c === 113) return 'documentation';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  if (a === 192 && b === 0 && c === 0) return 'protocol';
  return 'public';
}

function parseHexGroup(piece) {
  if (!/^[0-9A-Fa-f]{1,4}$/u.test(piece)) return null;
  return Number.parseInt(piece, 16);
}

function parseIpv6Side(text, allowEmbedded) {
  if (text === '') return { groups: [], embedded: false, valid: true };
  const pieces = text.split(':');
  if (pieces.some((piece) => piece.length === 0)) return { valid: false };
  const groups = [];
  let embedded = false;
  for (let index = 0; index < pieces.length; index += 1) {
    const piece = pieces[index];
    if (piece.includes('.')) {
      if (!allowEmbedded || index !== pieces.length - 1 || embedded) return { valid: false };
      const ipv4 = parseIpv4Like(piece);
      if (!ipv4 || !ipv4.valid || ipv4.obfuscated) return { valid: false };
      groups.push((ipv4.bytes[0] << 8) | ipv4.bytes[1], (ipv4.bytes[2] << 8) | ipv4.bytes[3]);
      embedded = true;
    } else {
      const group = parseHexGroup(piece);
      if (group === null) return { valid: false };
      groups.push(group);
    }
  }
  return { groups, embedded, valid: true };
}

export function parseIpv6Literal(text) {
  if (typeof text !== 'string' || text.length === 0 || text.length > 255 || /[\s%[\]]/u.test(text)) return null;
  const firstCompression = text.indexOf('::');
  if (firstCompression !== -1 && text.indexOf('::', firstCompression + 1) !== -1) return { valid: false, reason: 'multiple-compressions' };
  const compressed = firstCompression !== -1;
  const leftText = compressed ? text.slice(0, firstCompression) : text;
  const rightText = compressed ? text.slice(firstCompression + 2) : '';
  const left = parseIpv6Side(leftText, !compressed);
  const right = compressed ? parseIpv6Side(rightText, true) : { groups: [], embedded: false, valid: true };
  if (!left.valid || !right.valid || (left.embedded && compressed)) return { valid: false, reason: 'invalid-groups' };
  const explicit = left.groups.concat(right.groups);
  let groups;
  if (compressed) {
    if (explicit.length >= 8) return { valid: false, reason: 'compression-too-small' };
    const fill = Array(8 - explicit.length).fill(0);
    groups = left.groups.concat(fill, right.groups);
  } else {
    if (explicit.length !== 8) return { valid: false, reason: 'wrong-group-count' };
    groups = explicit;
  }
  const bytes = [];
  for (const group of groups) bytes.push((group >> 8) & 255, group & 255);
  return { valid: true, groups, bytes, embeddedIpv4Syntax: left.embedded || right.embedded };
}

function ipv4FromGroups(groups) {
  return [groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255];
}

export function ipv6Analysis(groups) {
  const allZero = groups.every((group) => group === 0);
  const loopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
  if (allZero) return { scope: 'unspecified', tunnel: null, embeddedIpv4: null };
  if (loopback) return { scope: 'loopback', tunnel: null, embeddedIpv4: null };
  if (groups[0] === 0xfd00 && groups[1] === 0x0ec2 && groups.slice(2, 7).every((group) => group === 0) && groups[7] === 0x23) {
    return { scope: 'metadata', tunnel: null, embeddedIpv4: null };
  }
  if (groups[0] === 0x0064 && groups[1] === 0xff9b && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0) {
    const embedded = ipv4FromGroups(groups);
    return { scope: 'tunnel', tunnel: 'nat64', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if (groups[0] === 0x0064 && groups[1] === 0xff9b && groups[2] === 1) {
    return { scope: 'tunnel', tunnel: 'nat64-local', embeddedIpv4: null };
  }
  if (groups[0] === 0x2002) {
    const embedded = [groups[1] >> 8, groups[1] & 255, groups[2] >> 8, groups[2] & 255];
    return { scope: 'tunnel', tunnel: '6to4', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if (groups[0] === 0x2001 && groups[1] === 0) {
    const embedded = [(groups[6] >> 8) ^ 255, (groups[6] & 255) ^ 255, (groups[7] >> 8) ^ 255, (groups[7] & 255) ^ 255];
    return { scope: 'tunnel', tunnel: 'teredo', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if ((groups[4] === 0x0000 || groups[4] === 0x0200) && groups[5] === 0x5efe) {
    const embedded = ipv4FromGroups(groups);
    return { scope: 'tunnel', tunnel: 'isatap', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    const embedded = ipv4FromGroups(groups);
    return { scope: 'tunnel', tunnel: 'ipv4-mapped', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if (groups.slice(0, 4).every((group) => group === 0) && groups[4] === 0xffff && groups[5] === 0) {
    const embedded = ipv4FromGroups(groups);
    return { scope: 'tunnel', tunnel: 'ipv4-translated', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if (groups.slice(0, 6).every((group) => group === 0) && !(groups[6] === 0 && (groups[7] === 0 || groups[7] === 1))) {
    const embedded = ipv4FromGroups(groups);
    return { scope: 'tunnel', tunnel: 'ipv4-compatible', embeddedIpv4: embedded, embeddedScope: ipv4Scope(embedded) };
  }
  if ((groups[0] & 0xfe00) === 0xfc00) return { scope: 'unique-local', tunnel: null, embeddedIpv4: null };
  if ((groups[0] & 0xffc0) === 0xfe80) return { scope: 'link-local', tunnel: null, embeddedIpv4: null };
  if ((groups[0] & 0xff00) === 0xff00) return { scope: 'multicast', tunnel: null, embeddedIpv4: null };
  if (groups[0] === 0x2001 && (groups[1] & 0xff00) === 0x0d00 && groups[1] !== 0x0db8) return { scope: 'protocol', tunnel: null, embeddedIpv4: null };
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return { scope: 'documentation', tunnel: null, embeddedIpv4: null };
  if (groups[0] === 0x2001 && (groups[1] & 0xfe00) === 0) return { scope: 'protocol', tunnel: null, embeddedIpv4: null };
  if (groups[0] === 0x0100 && groups.slice(1).every((group) => group === 0)) return { scope: 'discard', tunnel: null, embeddedIpv4: null };
  if (groups[0] < 0x2000 || groups[0] >= 0x4000) return { scope: 'reserved', tunnel: null, embeddedIpv4: null };
  return { scope: 'public', tunnel: null, embeddedIpv4: null };
}

export function internalHostname(hostname) {
  const lower = hostname.toLowerCase().replace(/\.$/u, '');
  if (lower === 'localhost' || lower.endsWith('.localhost')) return true;
  if (lower === 'local' || lower.endsWith('.local')) return true;
  if (lower === 'internal' || lower.endsWith('.internal')) return true;
  if (!lower.includes('.')) return true;
  return false;
}
