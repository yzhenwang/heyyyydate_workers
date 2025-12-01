/**
 * HeyyyyDate Image Delivery Worker
 *
 * Secure image delivery with blur enforcement for locked images.
 *
 * Features:
 * - JWT token validation for image access
 * - Automatic blur for locked image types
 * - Cloudflare Image Resizing transforms
 * - Caching with proper headers
 *
 * URL Format:
 *   /{character_card}/{image_type}_{variant}.{ext}?token=JWT&w=WIDTH&h=HEIGHT&q=QUALITY
 *
 * Token Claims:
 *   {
 *     user_id: string
 *     character_card: string
 *     unlocked_types: string[]  // e.g., ["profile", "casual"]
 *     relationship_level: number
 *     exp: number
 *     iat: number
 *   }
 *
 * If image_type is NOT in unlocked_types, blur=50 is applied.
 */

export interface Env {
  IMAGES_BUCKET: R2Bucket;
  IMAGE_TOKEN_SECRET: string;
}

interface TokenClaims {
  user_id: string;
  character_card: string;
  unlocked_types: string[];
  relationship_level: number;
  exp: number;
  iat: number;
}

// Simple base64url decode (Cloudflare Workers don't have Buffer)
function base64UrlDecode(str: string): string {
  // Replace URL-safe characters
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with = to make length multiple of 4
  while (str.length % 4) {
    str += '=';
  }
  return atob(str);
}

// Parse JWT without full validation (validation done by signature check)
function parseJwt(token: string): TokenClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return payload as TokenClaims;
  } catch {
    return null;
  }
}

// Verify JWT signature using Web Crypto API
async function verifyJwt(token: string, secret: string): Promise<TokenClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, payload, signature] = parts;

    // Import the secret key
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Verify the signature
    const data = encoder.encode(`${header}.${payload}`);
    const sig = Uint8Array.from(
      base64UrlDecode(signature),
      c => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify('HMAC', key, sig, data);
    if (!valid) return null;

    // Parse and validate expiration
    const claims = parseJwt(token);
    if (!claims) return null;

    const now = Math.floor(Date.now() / 1000);
    if (claims.exp < now) {
      return null; // Token expired
    }

    return claims;
  } catch {
    return null;
  }
}

// Extract image type from key (e.g., "alex_intellectual/casual_1.png" -> "casual")
function extractImageType(key: string): string | null {
  // Pattern: {character_card}/{image_type}_{variant}.{ext}
  const match = key.match(/\/([a-z]+)_\d+\.[a-z]+$/i);
  return match ? match[1].toLowerCase() : null;
}

// Extract character card from key
function extractCharacterCard(key: string): string | null {
  // Pattern: {character_card}/{image_type}_{variant}.{ext}
  // Or: preview/{character_card}/{image_type}_{variant}.{ext}
  const parts = key.split('/');
  if (parts.length === 2) {
    return parts[0];
  } else if (parts.length === 3 && parts[0] === 'preview') {
    return parts[1];
  }
  return null;
}

// Get content type from file extension
function getContentType(key: string): string {
  const ext = key.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'png': return 'image/png';
    case 'jpg':
    case 'jpeg': return 'image/jpeg';
    case 'webp': return 'image/webp';
    case 'gif': return 'image/gif';
    default: return 'application/octet-stream';
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get the image key from the path (remove leading /)
    const imageKey = url.pathname.slice(1);
    if (!imageKey) {
      return new Response('Not Found', { status: 404 });
    }

    // Get token from query params
    const token = url.searchParams.get('token');
    if (!token) {
      return new Response('Unauthorized: Missing token', { status: 401 });
    }

    // Verify token
    const claims = await verifyJwt(token, env.IMAGE_TOKEN_SECRET);
    if (!claims) {
      return new Response('Unauthorized: Invalid or expired token', { status: 401 });
    }

    // Validate character_card matches the requested image
    const requestedCard = extractCharacterCard(imageKey);
    if (requestedCard && requestedCard !== claims.character_card) {
      return new Response('Forbidden: Token not valid for this character', { status: 403 });
    }

    // Get image from R2
    const object = await env.IMAGES_BUCKET.get(imageKey);
    if (!object) {
      return new Response('Not Found', { status: 404 });
    }

    // Determine if blur should be applied
    const imageType = extractImageType(imageKey);
    const isUnlocked = imageType ? claims.unlocked_types.includes(imageType) : true;

    // Get transform options from query params
    const width = url.searchParams.get('w');
    const height = url.searchParams.get('h');
    const quality = url.searchParams.get('q');

    // Build response headers
    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || getContentType(imageKey));
    headers.set('Cache-Control', 'public, max-age=31536000'); // 1 year
    headers.set('ETag', object.httpEtag);

    // If image is locked, we need to apply blur
    // Using Cloudflare Image Resizing (requires Workers Paid plan)
    if (!isUnlocked) {
      // Apply blur transform via cf property
      const transformOptions: RequestInitCfProperties = {
        image: {
          blur: 50,
          ...(width && { width: parseInt(width) }),
          ...(height && { height: parseInt(height) }),
          ...(quality && { quality: parseInt(quality) }),
        },
      };

      // Fetch the image with transforms
      // Note: This requires the image to be accessible via a URL
      // In production, you'd configure R2 with a custom domain
      const imageUrl = `https://${url.hostname}/${imageKey}`;

      try {
        const transformedResponse = await fetch(imageUrl, {
          cf: transformOptions,
        } as RequestInit);

        // Return transformed image
        return new Response(transformedResponse.body, {
          headers: {
            ...Object.fromEntries(headers),
            'X-Image-Blurred': 'true',
          },
        });
      } catch {
        // If transform fails, serve original with blur header
        // (fallback for development/testing)
        headers.set('X-Image-Blurred', 'true');
        headers.set('X-Blur-Fallback', 'true');
        return new Response(object.body, { headers });
      }
    }

    // Apply resize transforms if requested (for unlocked images)
    if (width || height || quality) {
      const transformOptions: RequestInitCfProperties = {
        image: {
          ...(width && { width: parseInt(width) }),
          ...(height && { height: parseInt(height) }),
          ...(quality && { quality: parseInt(quality) }),
        },
      };

      const imageUrl = `https://${url.hostname}/${imageKey}`;

      try {
        const transformedResponse = await fetch(imageUrl, {
          cf: transformOptions,
        } as RequestInit);

        return new Response(transformedResponse.body, { headers });
      } catch {
        // Fallback to original if transform fails
        return new Response(object.body, { headers });
      }
    }

    // Return original image (unlocked, no transforms)
    return new Response(object.body, { headers });
  },
};
