package yaroslavtir;

/**
 * @author ymolodkov on 01.09.16.
 */

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import sun.text.normalizer.UTF16;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Created by gsenff on 8/24/16.
 */
public class JenrickPasswordEncoder {

    public static final String base64DotNetEncodedHash = "";
    public static final String examplePassword = "";

    // Facts supplied
    public static final int HEADER_BYTE_COUNT = 8;
    public final static int SALT_BYTES = 32;
    public final static int HASH_BYTES = 32;
    public final static int PBKDF2_ITERATIONS = 4096;


    // To byte array in .net reverses the bytes
    private final static int MAGIC_NUMBER = 0x05C0F0F1;


    public static class PasswordHashParts {
        private final int magic;
        private final int iterations;
        private final byte[] salt;
        private final byte[] hash;
        private final int hashByteLength;


        public PasswordHashParts(int magic, int iterations, byte[] salt, byte[] hash, int hashByteLength) {
            this.magic = magic;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
            this.hashByteLength = hashByteLength;
        }

        public static PasswordHashParts create(String base64encoded) {
            byte[] bytes = Base64.decodeBase64(base64encoded);


//            Arrays.copyOfRange()

            if (bytes == null) {
                System.out.println("No bytes were decoded from base64");
                return null;
            }
            if (bytes.length <= HEADER_BYTE_COUNT) {
                System.out.println("Invalid bytes found. Header should exist of at least [magic packet 4 bytes][iteration count 2 bytes][salt length 1 byte][hash length 1 byte], but only found " + bytes.length + " bytes.");
                return null;
            }

            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

            int magic = byteBuffer.getInt();          // 4
            int iterations = byteBuffer.getChar();    // 2
            int saltByteLength = byteBuffer.get();    // 1
            int hashByteLength = byteBuffer.get();    // 1

            if (iterations != 4096) {
                System.out.print("Iterations was expected to be 4096 but is: " + iterations);
            }

            if (magic != MAGIC_NUMBER) {
                System.out.print("Invalid password bytes. Parsed header, but it did not start with the magic number: " + MAGIC_NUMBER);
                return null;
            }

            int totalExpectedBytes = (saltByteLength + hashByteLength + HEADER_BYTE_COUNT);
            if (totalExpectedBytes < bytes.length) {
                System.out.print("Invalid password bytes. Header length + salt byte length + hash byte length = " + totalExpectedBytes + " exceeded the amount of available bytes in the byte array: " + bytes.length);
                return null;
            }

            byte[] salt = new byte[saltByteLength];
            byte[] hash = new byte[hashByteLength];

            byteBuffer.get(salt).array();
            byteBuffer.get(hash).array();

            return new PasswordHashParts(magic, iterations, salt, hash, hashByteLength);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Hash: ");
            sb.append(Base64.encodeBase64String(this.getHash()));
            sb.append("\n");
            sb.append("Salt: ");
            sb.append(Base64.encodeBase64String(this.getSalt()));
            sb.append("\n");
            sb.append("Magic number: ");
            sb.append(new Integer(MAGIC_NUMBER));
            sb.append("\n");
            return sb.toString();
        }

        public int getMagic() {
            return magic;
        }

        public int getIterations() {
            return iterations;
        }

        public byte[] getSalt() {
            return salt;
        }

        public byte[] getHash() {
            return hash;
        }

        public int getHashByteLength() {
            return hashByteLength;
        }
    }


    public static void main(String args[]) throws Exception {
        // Testing endianess
        PasswordHashParts passwordHashParts = PasswordHashParts.create(base64DotNetEncodedHash);
        System.out.println("real hash: " + Base64.encodeBase64String(passwordHashParts.getHash()));

        //workaround, can be a problem!
        byte[] bytes = pbkdf2(getCharArrayWithEncode(examplePassword, "UTF-16LE"), passwordHashParts.getSalt(), passwordHashParts.getIterations(), passwordHashParts.getHashByteLength());
        System.out.println("hash from password, standard java security: " + Base64.encodeBase64String(bytes));

        //some class from github I am not sure it is trustworthy
        Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(examplePassword.getBytes("UTF-16LE"), passwordHashParts.getSalt(), 4096);
        byte[] bytes1 = rfc2898DeriveBytes.getBytes(32);
        System.out.println("hash from password, class from github : " + Base64.encodeBase64String(bytes1));
    }

    //it is not real char array,
    private static char[] getCharArrayWithEncode(String str, String charsetName) throws UnsupportedEncodingException {
        byte[] bytes = str.getBytes(charsetName);
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) (bytes[i] & 0xFF);
        }
        return chars;
    }

    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }


}
