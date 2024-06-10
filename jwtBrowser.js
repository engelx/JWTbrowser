function createKey(clearKey) {
        return crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(clearKey),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify']
        );
    }
    
    function createSignature(clearKey, payload) {
        return createKey(clearKey)
            .then(key => crypto.subtle.sign(
                'HMAC', 
                key, 
                new TextEncoder().encode(payload)
            ));
    }
    
    function verifySignature(clearKey, payload) {
        return createKey(clearKey)
            .then(key => {
                const token = payload.replaceAll("-", "+").replaceAll("_", "/").split(".");
                const signedData = `${token[0]}.${token[1]}`;
                const signature = token[2];
                return crypto.subtle.verify(
                    "HMAC",
                    key,
                    Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
                    new TextEncoder().encode(signedData) 
                );
            });
    }
    
    function generateJWTToken(clearKey, payload) {
        const encodedHeader = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
        const encodedPayload = btoa(JSON.stringify(payload));
        const data = `${encodedHeader}.${encodedPayload}`.replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
        return createSignature(clearKey, data)
            .then(signature => {
                const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
                return `${data}.${encodedSignature}`;
            });
    }
