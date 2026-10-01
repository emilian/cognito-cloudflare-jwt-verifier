import { jwtVerify, JWK, errors, importJWK } from 'jose';
import decode from './decode';
import { JwtInvalidError } from './errors';
import { JwtCognitoClaimValidationError, JwtVerificationError, JwksNoMatchingKeyError } from './errors';

export type AWS_JWK = {
  kid: string;
  alg: string;
  kty: string;
  e: string;
  n: string;
  use: string;
};

function handleVerificationError(e: Error) {
  if (
    e instanceof errors.JOSEError &&
    [
      'ERR_JWT_CLAIM_VALIDATION_FAILED',
      'ERR_JWT_EXPIRED',
      'ERR_JWT_INVALID',
      'ERR_JWS_INVALID',
      'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
      'ERR_JOSE_ALG_NOT_ALLOWED',
    ].includes(e.code)
  ) {
    throw new JwtVerificationError(e);
  }

  if (isNoMatchingKeyError(e)) {
    throw new JwksNoMatchingKeyError(e);
  }

  throw e;
}

function isNoMatchingKeyError(e: Error) {
  return e instanceof errors.JOSEError && e.code === 'ERR_JWKS_NO_MATCHING_KEY';
}

function validateTokenUseClaim(payload: any, tokenType: 'id' | 'access') {
  if (!payload.token_use || payload.token_use !== tokenType) {
    const originalError = new JwtCognitoClaimValidationError(
      'token_use',
      `expected "${tokenType}", got "${payload.token_use}"`,
    );

    throw new JwtVerificationError(originalError);
  }
}

function validateClientIdClaim(payload: any, appClientId: string) {
  if (payload.client_id !== appClientId) {
    const originalError = new JwtCognitoClaimValidationError(
      'client_id',
      `expected "${appClientId}", got "${payload.client_id}"`,
    );

    throw new JwtVerificationError(originalError);
  }
}

// keyed by issuer and kid so keys from one issuer can never be used for another
const jwkCache = new Map<string, JWK>();

export async function getJwkByKid(iss: string, kid: string) {
  const cacheKey = `${iss}#${kid}`;
  const cached = jwkCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  const jwksEndpoint = iss + '/.well-known/jwks.json';
  const result = await fetch(jwksEndpoint, {
    cf: {
      cacheEverything: true,
      cacheTtlByStatus: {
        '200-299': 864000, // 10 days
        404: 1,
        '500-599': 0,
      },
    },
  });
  if (!result.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksEndpoint}: ${result.status}`);
  }
  const { keys } = (await result.json()) as {
    keys: (JWK & AWS_JWK)[];
  };

  for (const key of keys) {
    jwkCache.set(`${iss}#${key.kid}`, key);
  }
  const jwk = jwkCache.get(cacheKey);
  if (!jwk) {
    throw new JwksNoMatchingKeyError(new Error(`No key with kid "${kid}" in ${jwksEndpoint}`));
  }
  return jwk;
}

export function getJwt(str: string) {
  const match = str && /^Bearer\s+(\S+)\s*$/i.exec(str);
  return match ? match[1] : null;
}

export function getVerifier({
  awsRegion,
  userPoolId,
  appClientId,
  tokenType,
}: {
  awsRegion: string;
  userPoolId: string;
  appClientId: string;
  tokenType: 'id' | 'access';
}) {
  if (!crypto || !crypto.subtle) throw new Error('Crypto not supported, are you deploying to Cloudflare Worker?');

  // Never derive the issuer (and therefore the JWKS URL) from the unverified token.
  const issuer = `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}`;

  return {
    verify: async (authHeader: string) => {
      const token = getJwt(authHeader);
      if (!token) throw new JwtInvalidError();
      let header, payload;
      try {
        ({ header, payload } = decode(token));
      } catch {
        throw new JwtInvalidError();
      }
      const { kid } = header;

      if (!payload.iss || !kid) throw new JwtInvalidError();
      if (payload.iss !== issuer) {
        throw new JwtVerificationError(
          new JwtCognitoClaimValidationError('iss', `expected "${issuer}", got "${payload.iss}"`),
        );
      }

      const jwk = await getJwkByKid(issuer, kid);

      try {
        const key = await importJWK(jwk, 'RS256');
        const result = await jwtVerify(token, key, {
          algorithms: ['RS256'],
          audience: tokenType === 'id' ? appClientId : undefined,
          issuer,
        });
        validateTokenUseClaim(result.payload, tokenType);
        if (tokenType === 'access') validateClientIdClaim(result.payload, appClientId);

        return result;
      } catch (e) {
        handleVerificationError(e as Error);
      }
    },
  };
}

export function isJwtError(e: Error) {
  if (
    e instanceof JwksNoMatchingKeyError ||
    e instanceof JwtVerificationError ||
    e instanceof JwtInvalidError ||
    e instanceof JwtCognitoClaimValidationError
  ) {
    return true;
  }
  return false;
}

export {
  JwtCognitoClaimValidationError,
  JwtVerificationError,
  JwksNoMatchingKeyError,
  JwtInvalidError,
} from './errors';
export * as decode from './decode';
export type { JWK, JWTPayload, JWTVerifyResult } from 'jose';
