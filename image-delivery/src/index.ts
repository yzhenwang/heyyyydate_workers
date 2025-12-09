/**
 * HeyyyyDate Image Delivery Worker
 *
 * Secure image delivery with blur enforcement and image transforms.
 *
 * Architecture: Per-image tokens (Option A)
 * - Each image URL has its own token with a simple blur flag
 * - Backend decides what should be blurred, Worker just enforces
 * - Worker is a "dumb enforcer" - no unlock logic needed
 *
 * Features:
 * - JWT token validation for image access
 * - Blur enforcement based on token's "blur" flag
 * - Resize and format transforms (width, height, quality, format)
 * - Two-layer caching (CF Cache API + R2 transformed bucket)
 * - Presigned URLs for private R2 access
 *
 * Architecture:
 * - IMAGES_BUCKET: Original images (source of truth)
 * - TRANSFORMED_IMAGES: Cached transformed versions
 *
 * URL Format:
 *   /{image_key}?token=JWT[&w=WIDTH&h=HEIGHT&q=QUALITY&f=FORMAT]
 *
 * Token Claims (simple - backend decides blur):
 *   {
 *     image_key: string    // e.g., "alex_intellectual/casual_1.png"
 *     blur: boolean        // Backend's decision: should this image be blurred?
 *     exp: number
 *     iat: number
 *   }
 */

export interface Env {
  IMAGES_BUCKET: R2Bucket;           // Character images (AI-generated)
  USER_IMAGES_BUCKET: R2Bucket;      // User-uploaded images
  TRANSFORMED_IMAGES: R2Bucket;
  IMAGE_TOKEN_SECRET: string;
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  R2_ACCOUNT_ID?: string;
  ALLOWED_ORIGINS?: string;
}

interface TransformOptions {
  blur?: number;
  width?: number;
  height?: number;
  quality?: number;
  format?: string;
}

interface TokenClaims {
  image_key: string;
  blur: boolean;
  user_id?: string;  // Optional for backwards compatibility
  exp: number;
  iat: number;
}

// Default blur radius for locked images
const BLUR_RADIUS = 50;

// R2 endpoint format
const getR2Endpoint = (accountId: string) =>
  `https://${accountId}.r2.cloudflarestorage.com`;

// ============================================================================
// AWS Signature V4 Implementation for Presigned URLs
// ============================================================================

async function hmacSha256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
}

async function sha256(message: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message));
  return arrayBufferToHex(hash);
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function getSignatureKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const kDate = await hmacSha256(new TextEncoder().encode('AWS4' + secretKey), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  return hmacSha256(kService, 'aws4_request');
}

async function generatePresignedUrl(
  accessKeyId: string,
  secretAccessKey: string,
  accountId: string,
  bucket: string,
  key: string,
  expiresIn: number = 3600
): Promise<string> {
  const region = 'auto';
  const service = 's3';
  const host = `${accountId}.r2.cloudflarestorage.com`;
  const endpoint = `https://${host}`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const canonicalUri = `/${bucket}/${key}`;

  const queryParams = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': expiresIn.toString(),
    'X-Amz-SignedHeaders': 'host',
  });

  // Sort query parameters
  queryParams.sort();
  const canonicalQueryString = queryParams.toString();

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    'GET',
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const canonicalRequestHash = await sha256(canonicalRequest);

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    canonicalRequestHash,
  ].join('\n');

  const signingKey = await getSignatureKey(secretAccessKey, dateStamp, region, service);
  const signatureBuffer = await hmacSha256(signingKey, stringToSign);
  const signature = arrayBufferToHex(signatureBuffer);

  queryParams.set('X-Amz-Signature', signature);

  return `${endpoint}${canonicalUri}?${queryParams.toString()}`;
}

// ============================================================================
// JWT Validation
// ============================================================================

function base64UrlDecode(str: string): string {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return atob(str);
}

function parseJwt(token: string): TokenClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(base64UrlDecode(parts[1])) as TokenClaims;
  } catch {
    return null;
  }
}

async function verifyJwt(token: string, secret: string): Promise<TokenClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, payload, signature] = parts;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const data = encoder.encode(`${header}.${payload}`);
    const sig = Uint8Array.from(base64UrlDecode(signature), c => c.charCodeAt(0));

    const valid = await crypto.subtle.verify('HMAC', key, sig, data);
    if (!valid) return null;

    const claims = parseJwt(token);
    if (!claims) return null;

    const now = Math.floor(Date.now() / 1000);
    if (claims.exp < now) return null;

    return claims;
  } catch {
    return null;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

function getContentType(key: string): string {
  const ext = key.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'png': return 'image/png';
    case 'jpg':
    case 'jpeg': return 'image/jpeg';
    case 'webp': return 'image/webp';
    case 'avif': return 'image/avif';
    case 'gif': return 'image/gif';
    default: return 'application/octet-stream';
  }
}

function parseTransformOptions(url: URL): TransformOptions {
  const options: TransformOptions = {};

  const w = url.searchParams.get('w');
  const h = url.searchParams.get('h');
  const q = url.searchParams.get('q');
  const f = url.searchParams.get('f');

  if (w) options.width = parseInt(w);
  if (h) options.height = parseInt(h);
  if (q) options.quality = parseInt(q);
  if (f && ['webp', 'avif', 'jpeg', 'png'].includes(f)) options.format = f;

  return options;
}

function getCacheKey(imageKey: string, options: TransformOptions, isBlurred: boolean): string {
  const parts = [imageKey];

  if (isBlurred) parts.push(`blur${BLUR_RADIUS}`);
  if (options.width) parts.push(`w${options.width}`);
  if (options.height) parts.push(`h${options.height}`);
  if (options.quality) parts.push(`q${options.quality}`);
  if (options.format) parts.push(`f${options.format}`);

  // Replace special chars and join with underscores
  return parts.join('_').replace(/[^a-zA-Z0-9/_.-]/g, '_');
}

// ============================================================================
// Bucket Selection
// ============================================================================

function getSourceBucket(env: Env, imageKey: string): R2Bucket {
  // User-uploaded images: user-images/{user_id}/{image_id}.jpg
  if (imageKey.startsWith('user-images/')) {
    return env.USER_IMAGES_BUCKET;
  }

  // Character images: {character_id}/{category}/{image_name}.png
  return env.IMAGES_BUCKET;
}

// ============================================================================
// CORS Handling
// ============================================================================

const corsHeaders = {
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = env.ALLOWED_ORIGINS
    ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : ['http://localhost:3000', 'http://localhost:8000', 'http://localhost:8081', 'https://heyyyydate.com'];

  const isAllowed = allowedOrigins.some(allowed => {
    if (allowed === '*') return true;
    if (allowed === origin) return true;
    if (allowed.startsWith('*.')) {
      return origin.endsWith(allowed.slice(1));
    }
    return false;
  });

  return {
    ...corsHeaders,
    'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
  };
}

// ============================================================================
// Main Worker Handler
// ============================================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cors = getCorsHeaders(request, env);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // Health check endpoint
    if (url.pathname === '/health') {
      const health: Record<string, unknown> = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        images_bucket_configured: !!env.IMAGES_BUCKET,
        user_images_bucket_configured: !!env.USER_IMAGES_BUCKET,
        transformed_bucket_configured: !!env.TRANSFORMED_IMAGES,
        presigned_urls_configured: !!(env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY),
      };

      if (env.IMAGES_BUCKET) {
        try {
          const list = await env.IMAGES_BUCKET.list({ limit: 1 });
          health.images_bucket_accessible = true;
          health.images_bucket_count = list.objects.length > 0 ? '1+' : '0';
        } catch (e) {
          health.images_bucket_accessible = false;
          health.images_bucket_error = e instanceof Error ? e.message : 'Unknown error';
          health.status = 'degraded';
        }
      }

      if (env.USER_IMAGES_BUCKET) {
        try {
          const list = await env.USER_IMAGES_BUCKET.list({ limit: 1 });
          health.user_images_bucket_accessible = true;
          health.user_images_bucket_count = list.objects.length > 0 ? '1+' : '0';
        } catch (e) {
          health.user_images_bucket_accessible = false;
          health.user_images_bucket_error = e instanceof Error ? e.message : 'Unknown error';
          health.status = 'degraded';
        }
      }

      if (env.TRANSFORMED_IMAGES) {
        try {
          const list = await env.TRANSFORMED_IMAGES.list({ limit: 1 });
          health.transformed_bucket_accessible = true;
          health.transformed_bucket_count = list.objects.length > 0 ? '1+' : '0';
        } catch (e) {
          health.transformed_bucket_accessible = false;
          health.transformed_bucket_error = e instanceof Error ? e.message : 'Unknown error';
          health.status = 'degraded';
        }
      }

      return new Response(JSON.stringify(health, null, 2), {
        headers: { 'Content-Type': 'application/json', ...cors },
      });
    }

    // Get image key from path
    const imageKey = url.pathname.slice(1);
    if (!imageKey) {
      return new Response('Not Found', { status: 404, headers: cors });
    }

    // Validate token
    const token = url.searchParams.get('token');
    if (!token) {
      return new Response('Unauthorized: Missing token', { status: 401, headers: cors });
    }

    const claims = await verifyJwt(token, env.IMAGE_TOKEN_SECRET);
    if (!claims) {
      return new Response('Unauthorized: Invalid or expired token', { status: 401, headers: cors });
    }

    // Validate image_key matches what's in the token
    // This prevents token reuse for different images
    if (claims.image_key && claims.image_key !== imageKey) {
      return new Response('Forbidden: Token not valid for this image', { status: 403, headers: cors });
    }

    // Get source bucket based on image key prefix
    const sourceBucket = getSourceBucket(env, imageKey);

    // Check if image exists
    const originalExists = await sourceBucket.head(imageKey);
    if (!originalExists) {
      return new Response('Not Found', { status: 404, headers: cors });
    }

    // Read blur decision directly from token - backend already decided
    // No unlock logic here - Worker is just an enforcer
    const shouldBlur = claims.blur === true;

    const transformOptions = parseTransformOptions(url);
    const needsTransform = shouldBlur || Object.keys(transformOptions).length > 0;

    // Build cache key
    const cacheKey = getCacheKey(imageKey, transformOptions, shouldBlur);

    // Check Cloudflare Cache API first
    const cache = caches.default;
    const cacheUrl = new URL(request.url);
    cacheUrl.search = ''; // Remove query params for cache key
    cacheUrl.pathname = '/' + cacheKey;

    const cachedResponse = await cache.match(cacheUrl.toString());
    if (cachedResponse) {
      const headers = new Headers(cachedResponse.headers);
      headers.set('X-Cache', 'HIT');
      headers.set('X-Image-Blurred', shouldBlur ? 'true' : 'false');
      for (const [key, value] of Object.entries(cors)) {
        headers.set(key, value);
      }
      return new Response(cachedResponse.body, { headers });
    }

    // Check R2 transformed cache
    if (needsTransform) {
      const transformedObject = await env.TRANSFORMED_IMAGES.get(cacheKey);
      if (transformedObject) {
        const headers = new Headers();
        headers.set('Content-Type', transformedObject.httpMetadata?.contentType || getContentType(imageKey));
        headers.set('Cache-Control', 'public, max-age=31536000');
        headers.set('ETag', transformedObject.httpEtag);
        headers.set('X-Cache', 'HIT-R2');
        headers.set('X-Image-Blurred', shouldBlur ? 'true' : 'false');
        for (const [key, value] of Object.entries(cors)) {
          headers.set(key, value);
        }

        const response = new Response(transformedObject.body, { headers });

        // Store in CF Cache
        await cache.put(cacheUrl.toString(), response.clone());

        return response;
      }
    }

    // No cached version - need to fetch/transform
    if (needsTransform && env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY) {
      // Generate presigned URL for the original image
      const accountId = env.R2_ACCOUNT_ID || env.R2_ACCESS_KEY_ID.split('/')[0] || '';

      // Determine bucket name based on image key prefix
      const bucketName = imageKey.startsWith('user-images/') ? 'user-images' : 'character-images';

      const presignedUrl = await generatePresignedUrl(
        env.R2_ACCESS_KEY_ID,
        env.R2_SECRET_ACCESS_KEY,
        accountId,
        bucketName,
        imageKey,
        300 // 5 minute expiry for internal use
      );

      // Build Cloudflare Image Resizing options
      const cfImageOptions: Record<string, unknown> = {};
      if (shouldBlur) cfImageOptions.blur = BLUR_RADIUS;
      if (transformOptions.width) cfImageOptions.width = transformOptions.width;
      if (transformOptions.height) cfImageOptions.height = transformOptions.height;
      if (transformOptions.quality) cfImageOptions.quality = transformOptions.quality;
      if (transformOptions.format) cfImageOptions.format = transformOptions.format;

      // Auto-detect best format from Accept header
      if (!cfImageOptions.format) {
        const accept = request.headers.get('Accept') || '';
        if (accept.includes('image/avif')) {
          cfImageOptions.format = 'avif';
        } else if (accept.includes('image/webp')) {
          cfImageOptions.format = 'webp';
        }
      }

      try {
        const transformedResponse = await fetch(presignedUrl, {
          cf: { image: cfImageOptions },
        } as RequestInit);

        if (transformedResponse.ok) {
          const blob = await transformedResponse.blob();

          // Store in R2 transformed cache
          await env.TRANSFORMED_IMAGES.put(cacheKey, blob, {
            httpMetadata: { contentType: blob.type },
          });

          const headers = new Headers();
          headers.set('Content-Type', blob.type);
          headers.set('Cache-Control', 'public, max-age=31536000');
          headers.set('X-Cache', 'MISS');
          headers.set('X-Image-Blurred', shouldBlur ? 'true' : 'false');
          for (const [key, value] of Object.entries(cors)) {
            headers.set(key, value);
          }

          const response = new Response(blob.stream(), { headers });

          // Store in CF Cache
          await cache.put(cacheUrl.toString(), response.clone());

          return response;
        } else {
          console.error(`Transform failed: ${transformedResponse.status} ${transformedResponse.statusText}`);
          // SECURITY: If blur was required, don't serve unblurred original
          if (shouldBlur) {
            return new Response('Image processing failed for locked content', {
              status: 500,
              headers: { 'Content-Type': 'text/plain', ...cors },
            });
          }
          // Fall through to serve original only if blur was NOT required
        }
      } catch (e) {
        console.error('Transform error:', e);
        // SECURITY: If blur was required, don't serve unblurred original
        if (shouldBlur) {
          return new Response('Image processing failed for locked content', {
            status: 500,
            headers: { 'Content-Type': 'text/plain', ...cors },
          });
        }
        // Fall through to serve original only if blur was NOT required
      }
    }

    // SECURITY CHECK: Never serve unblurred original if blur was required
    if (shouldBlur) {
      console.error('Security: Refusing to serve unblurred image when blur was required');
      return new Response('Image processing unavailable for locked content', {
        status: 500,
        headers: { 'Content-Type': 'text/plain', ...cors },
      });
    }

    // Fallback: serve original from R2 (only for unlocked images with no transforms)
    const object = await sourceBucket.get(imageKey);
    if (!object) {
      return new Response('Not Found', { status: 404, headers: cors });
    }

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || getContentType(imageKey));
    headers.set('Cache-Control', 'public, max-age=31536000');
    headers.set('ETag', object.httpEtag);
    headers.set('X-Cache', 'BYPASS');
    headers.set('X-Image-Blurred', 'false');
    for (const [key, value] of Object.entries(cors)) {
      headers.set(key, value);
    }

    return new Response(object.body, { headers });
  },
};
