package HybridEncryption;
 
import java.math.BigInteger;
import java.util.Random;

import java.io.File;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

class RSA {

    // Variables
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 1024;
    private Random r;
 
    // Constructors
    public RSA(){
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
    }
 
    public RSA(BigInteger e, BigInteger d, BigInteger N){
        this.e = e;
        this.d = d;
        this.N = N;
    }
 
    // Convert Bytes to String
    protected static String bytesToString(byte[] encrypted){
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
 
    // Encrypt
    public byte[] encrypt(byte[] message){
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }
 
    // Decrypt
    public byte[] decrypt(byte[] message){
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
    
} 

class AES extends RSA {
 
    // Generate Secret Key
    public static SecretKey getSecretEncryptionKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // AES Key Size
        SecretKey secKey = generator.generateKey();
        return secKey;
    }
    
    // Encrypt Plaintext using AES
    public static byte[] encryptText(String plainText,SecretKey secKey) throws Exception{
		// AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }
    
    // Decrypt Ciphertext using AES
    public static String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
	// AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }
    
    // Convert Bytes to Hex
    protected static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }

}

public class HybridEncryption extends AES{
        public static void main(String[] args) throws Exception {
            Scanner sc = new Scanner(System.in);
            
            // Get txt filename
            System.out.print("Enter txt file name: ");
            String filename = sc.nextLine();
            
            // Read plaintext
            Scanner readfile = new Scanner(new File(filename));
            String plaintext = "";
            
            while(readfile.hasNext()){
                plaintext = plaintext + readfile.nextLine();
            }
            
            System.out.println("Plain Text:" + plaintext);
            System.out.println();
            
            // AES Encryption
            System.out.println("Encryption");
            SecretKey secKey = getSecretEncryptionKey();
            byte[] cipherText = encryptText(plaintext, secKey);
        
            System.out.println("AES Key (Hex Form):" + bytesToHex(secKey.getEncoded()));
            System.out.println("Encrypted Text (Hex Form):"+bytesToHex(cipherText));
        
            //RSA Encryption
            RSA rsa = new RSA();
            byte[] encrypted = rsa.encrypt(cipherText);
            System.out.println("RSA encrypted data:" + encrypted);
            
            System.out.println();
            
            // Decryption
            System.out.println("Decryption");
            byte[] decrypted = rsa.decrypt(encrypted);
            System.out.println("RSA Decrypting Bytes: " + bytesToString(decrypted));
            System.out.println("Decrypted String: " + new String(decrypted));
        
            String decryptedText = decryptText(cipherText, secKey);
            System.out.println("Descrypted Text:" + decryptedText);
        
    }
}

