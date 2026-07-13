se64 format
 * @returns {string} The decrypted UTF-8 string
 * @throws {Error} May throw errors for invalid inputs or decryption failures
 *
 * @example
 * // Example usage (with actual encrypted data)
 * const decrypted = decryptAES(
 *     'MTIzNDU2Nzg5MDEyMzQ1Ng==...',  // IV + ciphertext
 *     'c2VjcmV0LWtleS1kYXRhCg=='      // Key
 * );
 *
 * @requires crypto Node.js crypto module
 * @see {@link module:api~changeBase64Type|Function ChangeBase64Type} for Base64 format conversion
 */
function decryptAES(pp1, pp2) {
    // Convert from URL-safe Base64 to standard Base64
    pp1 = changeBase64Type(pp1, 2);
    pp2 = changeBase64Type(pp2, 2);
    
    // Extract ciphertext (after first 16 bytes) and IV (first 16 bytes)
    const cipherText = pp1.substring(16);
    const key = Buffer.from(pp2, 'utf8');
    const iv = Buffer.from(pp1.substring(0, 16), 'utf8');
    
    // Create decipher with AES-128-CBC algorithm
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    
    // Perform decryption
    let decrypted = decipher.update(cipherText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

/**
 * Encrypts data using RSA with a public key, with optional MD5 preprocessing
 * <br>
 * <br>Supports two encryption modes:
 * <br>1. Direct encryption of the message (default)
 * <br>2. MD5 hash preprocessing (applies MD5 + length padding before encryption)
 *
 * @param {string} message - The plaintext message to encrypt
 * @param {string|Buffer} publicKeyPEM - RSA public key in PEM format
 * @param {number} [mode=1] - Encryption mode:
 *                            1 = direct encryption,
 *                            2 = MD5 hash preprocessing
 * @returns {string} Base64-encoded encrypted data
 * @throws {Error} May throw errors for invalid keys or encryption failures
 *
 * @example
 * // Direct encryption
 * encryptRSA('secret message', publicKey);
 *
 * // With MD5 preprocessing
 * encryptRSA('secret message', publicKey, 2);
 *
 * @requires crypto Node.js crypto module
 */
function encryptRSA(message, publicKeyPEM, mode = 1) {
    // Mode 2: Apply MD5 hash and length padding
    if (mode === 2) {
        const md5 = crypto.createHash('md5').update(message).digest('hex');
        message = md5 + (md5.length<10?'0':'') + md5.length;
    }
    
    // Convert message to Buffer
    const buffer = Buffer.from(message, 'utf8');
    
    // Perform RSA encryption
    const encrypted = crypto.publicEncrypt({
        key: publicKeyPEM,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, buffer);
    
    // Return as Base64 string
    return encrypted.toString('base64');
}

/**
 * Generates a pseudo-random SHA-1 hash from combined client parameters
 * <br>
 * <br>Creates a deterministic hash value by combining multiple client-specific parameters.
 * <br>This is typically used for generating session tokens or unique identifiers.
 *
 * @param {string} [client='web'] - Client identifier (e.g., 'web', 'mobile')
 * @param {string} seval - Session evaluation parameter
 * @param {string} encpwd - Encrypted password or password hash
 * @param {string} email - User's email address
 * @param {string} [browserid=''] - Browser fingerprint or identifier
 * @param {string} random - Random value
 * @returns {string} SHA-1 hash of the combined parameters (40-character hex string)
 *
 * @example
 * // Basic usage
 * const token = prandGen('web', 'session123', 'encryptedPwd', 'user@example.com', 'browser123', 'randomValue');
 *
 * // With default client and empty browserid
 * const token = prandGen(undefined, 'session123', 'encryptedPwd', 'user@example.com', '', 'randomValue');
 *
 * @requires crypto Node.js crypto module
 */
function prandGen(client = 'web', seval, encpwd, email, browserid = '', random) {
    // Combine all parameters with hyphens
    const combined = `${client}-${seval}-${encpwd}-${email}-${browserid}-${random}`;
    
    // Generate SHA-1 hash and return as hex string
    return crypto.createHash('sha1').update(combined).digest('hex');
}

/**
 * TeraBoxApp API client class
 *
 * Provides a comprehensive interface for interacting with TeraBox services,
 * including encryption utilities, API request handling, and session management.
 *
 * @class
 * @property {module:api~FormUrlEncoded   } FormUrlEncoded - Form URL encoding utility
 * @property {module:api~signDownload     } SignDownload - Download signature generator
 * @property {module:api~checkMd5val      } CheckMd5Val - MD5 hash validator (single)
 * @property {module:api~checkMd5arr      } CheckMd5Arr - MD5 hash validator (array)
 * @property {module:api~decodeMd5        } DecodeMd5 - Custom MD5 transformation
 * @property {module:api~changeBase64Type } ChangeBase64Type - Base64 format converter
 * @property {module:api~decryptAES       } DecryptAES - AES decryption utility
 * @property {module:api~encryptRSA       } EncryptRSA - RSA encryption utility
 * @property {module:api~prandGen         } PRandGen - Pseudo-random hash generator
 *
 * @property {string} TERABOX_DOMAIN - Default TeraBox domain
 * @property {number} TERABOX_TIMEOUT - Default API timeout (10 seconds)
 *
 * @property {Object} data - Application data including tokens and keys
 * @property {string} data.csrf - CSRF token
 * @property {string} data.logid - Log ID
 * @property {string} data.pcftoken - PCF token
 * @property {string} data.bdstoken - BDS token
 * @property {string} data.jsToken - JavaScript token
 * @property {string} data.pubkey - Public key
 *
 * @property {TeraBoxAppParams} params - Application parameters and configuration
 */
class TeraBoxApp {
    // Encryption/Utility Methods 1
    FormUrlEncoded = FormUrlEncoded;
    SignDownload = signDownload;
    CheckMd5Val = checkMd5val;
    CheckMd5Arr = checkMd5arr;
    DecodeMd5 = decodeMd5;
    
    // Encryption/Utility Methods 2
    ChangeBase64Type = changeBase64Type;
    DecryptAES = decryptAES;
    EncryptRSA = encryptRSA;
    PRandGen = prandGen;
    
    // Constants
    TERABOX_DOMAIN = 'terabox.com';
    TERABOX_TIMEOUT = 10000;
    
    // app data
    data = {
        csrf: '',
        logid: '0',
        pcftoken: '',
        bdstoken: '',
        jsToken: '',
        pubkey: '',
    };
    
    // Application parameters and configuration
    params = {
        whost: 'https://www.' + this.TERABOX_DOMAIN,
        uhost: 'https://c-jp.' + this.TERABOX_DOMAIN,
        lang: 'en',
        app: {
            app_id: 250528,
            web: 1,
            channel: 'dubox',
            clienttype: 0, // 5 is wap?
        },
        ver_android: '3.44.2',
        ua: 'terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox',
        cookie: '',
        auth: {},
        account_id: 0,
        account_name: '',
        is_vip: false,
        vip_type: 0,
        space_used: 0,
        space_total: Math.pow(1024, 3),
        space_available: Math.pow(1024, 3),
        cursor: 'null',
    };
    
    /**
     * Creates a new TeraBoxApp instance
     * @param {string} authData - Authentication data (NDUS token)
     * @param {string} [authType='ndus'] - Authentication type (currently only 'ndus' supported)
     * @throws {Error} Throws error if authType is not supported
     */
    constructor(authData, authType = 'ndus') {
        this.params.cookie = `lang=${this.params.lang}`;
        if(authType === 'ndus'){
            this.params.cookie += authData ? '; ndus=' + authData : '';
        }
        else{
            throw new Error('initTBApp', { cause: 'AuthType Not Supported!' });
        }
    }
    
    /**
     * Updates application data including tokens and user information
     * @param {string} [customPath] - Custom path to use for the update request
     * @param {number} [retries=4] - Number of retry attempts
     * @returns {Promise<Object>} The updated template data
     * @async
     * @throws {Error} Throws error if request fails or parsing fails
     */
    async updateAppData(customPath, retries = 4){
        const url = new URL(this.params.whost + (customPath ? `/${customPath}` : '/main'));
        
        try{
            const req = await request(url, {
                headers:{
                    'User-Agent': this.params.ua,
                    'Cookie': this.params.cookie,
                },
                signal: AbortSignal.timeout(this.TERABOX_TIMEOUT + 10000),
            });
            
            if(req.statusCode === 302){
                // FIX: the original code never decremented `retries` here,
                // so a 302 loop (e.g. cookie flagged, always redirecting)
                // would recurse forever. Now it actually counts down and
                // stops.
                if(retries <= 0){
                    throw new Error('updateAppData', { cause: 'Too many redirects (possible invalid/flagged cookie)' });
                }
                if(req.headers.location === '/login'){
                    req.headers.location = this.params.whost + '/login';
                }
                const newUrl = new URL(req.headers.location);
                if(this.params.whost !== newUrl.origin){
                    this.params.whost = newUrl.origin;
                    console.warn(`[WARN] Default hostname changed to ${newUrl.origin}`);
                }
                const toPathname = newUrl.pathname.replace(/^\//, '');
                const finalUrl = toPathname + newUrl.search;
                return await this.updateAppData(finalUrl, retries - 1);
            }
            
            if(req.headers['set-cookie']){
                const cJar = new CookieJar();
                this.params.cookie.split(';').map(cookie => cJar.setCookieSync(cookie, this.params.whost));
                if(typeof req.headers['set-cookie'] === 'string'){
                    req.headers['set-cookie'] = [req.headers['set-cookie']];
                }
                for(const cookie of req.headers['set-cookie']){
                    cJar.setCookieSync(cookie.split('; ')[0], this.params.whost);
                }
                this.params.cookie = cJar.getCookiesSync(this.params.whost).map(cookie => cookie.cookieString()).join('; ');
            }
            
 
