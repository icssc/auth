export async function hmacFromSecret(googleSecret: string): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(googleSecret),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign", "verify"]
    );
}

// https://www.technocatgames.com/blog/fast-arraybuffer-to-base64-in-javascript/

export function arrayBufferToBase64(buf: ArrayBuffer): string {
    // widen to utf-16, transmute to string, encode
    return btoa(
        new TextDecoder("UTF-16").decode(Uint16Array.from(new Uint8Array(buf)))
    );
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const array = Uint8Array.from(binaryString, (c) => c.charCodeAt(0));
    return array.buffer;
}
