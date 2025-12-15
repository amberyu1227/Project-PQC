import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

/**
 * PQC Migration & Security Rule Test Suite (Java Version)
 * 用於測試靜態代碼分析規則的觸發準確度。
 */
public class PQCTestSuite {

    // ==========================================
    // 1. 弱雜湊算法 (Weak Hashing)
    // ==========================================
    public void testWeakHashes() throws Exception {
        byte[] data = "Sensitive Data".getBytes();

        // [B324] WEAK_HASH_MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.digest(data);

        // [B303] WEAK_HASH_SHA1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.digest(data);
    }

    // ==========================================
    // 2. 弱加密算法 (Weak Ciphers)
    // ==========================================
    public void testWeakCiphers() throws Exception {
        // [B304] WEAK_CIPHER_DES
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        // [B304] WEAK_CIPHER_DES (Triple DES)
        Cipher tripleDesCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    }

    // ==========================================
    // 3. PQC 遷移目標與 AES 使用樣式
    // ==========================================
    public void testPQCTargetsAndAES() throws Exception {
        byte[] keyBytes = new byte[16];
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        // [B413_AES_WEAK] AES ECB Mode (Critical)
        Cipher weakCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        weakCipher.init(Cipher.ENCRYPT_MODE, key);

        // [B413_AES_SAFE] AES GCM (PQC Safe Asset but check params)
        Cipher gcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // [B416] RISKY_GCM_NONCE_LENGTH
        // 刻意使用 16 bytes IV (NIST 推薦 GCM IV 為 12 bytes)
        byte[] badNonce = new byte[16]; 
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, badNonce);
        gcmCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        // [B413_IV_WEAK] CBC Mode with static IV
        // 這裡模擬硬編碼的 IV 或者未隨機化的 IV
        Cipher cbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] staticIV = "1234567812345678".getBytes(); // Hardcoded IV
        IvParameterSpec ivSpec = new IvParameterSpec(staticIV);
        cbcCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    }

    // ==========================================
    // 4. 非對稱加密 (RSA/ECC) - PQC 核心目標
    // ==========================================
    public void testAsymmetricCrypto() throws Exception {
        // [B413_RSA_WEAK_SIZE] RSA < 2048
        KeyPairGenerator weakKpg = KeyPairGenerator.getInstance("RSA");
        weakKpg.initialize(1024);

        // [B413_RSA] RSA Key Generation (General PQC Target)
        KeyPairGenerator strongKpg = KeyPairGenerator.getInstance("RSA");
        strongKpg.initialize(2048);

        // [B413_ECC] ECC Usage
        KeyPairGenerator eccKpg = KeyPairGenerator.getInstance("EC");
        
        // [B415_ECC_WEAK_CURVE] 使用弱曲線 secp192r1
        ECGenParameterSpec weakCurve = new ECGenParameterSpec("secp192r1");
        eccKpg.initialize(weakCurve);

        // [B413_ECC] (Target) 使用 P-256
        ECGenParameterSpec strongCurve = new ECGenParameterSpec("secp256r1");
        eccKpg.initialize(strongCurve);
    }

    // ==========================================
    // 5. PQC 正面識別 (PQC Ready)
    // ==========================================
    public void testPQCReadyLibs() {
        // Java 雖然原生尚未完全支援，但通常透過 Bouncy Castle 或字串識別
        
        // [B501_KYBER] 模擬 Kyber (ML-KEM) 字串特徵
        String kemAlgo = "Kyber-1024";
        System.out.println("Initializing PQC: " + kemAlgo);

        // [B502_DILITHIUM] 模擬 Dilithium (ML-DSA) 字串特徵
        String sigAlgo = "Dilithium3";
        System.out.println("Signing with: " + sigAlgo);
    }

    // ==========================================
    // 6. [HARDCORE] 硬編碼與機密管理
    // ==========================================
    public void testHardcodedSecrets() {
        // [B702_HARDCODED_KEY] Generic Hardcoded Key
        String secretKey = "x8s#9@2!super_secret_key_value";

        // [B706_HARDCODED_PASSWORD]
        String dbPassword = "Password123!";

        // [B707_HARDCODED_AWS] AWS Access Key ID Pattern
        String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";

        // [B708_HARDCODED_TOKEN]
        String apiToken = "eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded";

        // [B709_HARDCODED_PQC_SK] PQC Private Key Pattern
        String pqcPrivateKey = "-----BEGIN PQC PRIVATE KEY-----...KyberSK...";
    }

    // ==========================================
    // 7. 隨機數與進階參數檢查
    // ==========================================
    public void testAdvancedParams() throws Exception {
        // [B701_WEAK_RNG] 使用 java.util.Random
        Random weakRand = new Random();
        int r = weakRand.nextInt();

        // [B703_WEAK_KDF_ITERATIONS] Iterations < 600,000
        int iterations = 1000; 
        char[] password = "password".toCharArray();
        byte[] salt = new byte[16];
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        skf.generateSecret(spec);

        // [B710_SHORT_SALT] Salt < 16 bytes
        byte[] shortSalt = new byte[8];
        new SecureRandom().nextBytes(shortSalt);
    }
}
