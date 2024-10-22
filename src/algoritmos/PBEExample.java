package algoritmos;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.util.encoders.Hex;

/**
 * A simple example of PBE mode.
 */
public class PBEExample
{
    public static void main(String[] args)
        throws Exception
    {
        char[] passwd	= "passwd".toCharArray();
        int iterationCount = 100;
        byte[] salt = Hex.decode("0102030405060708");
        String algorithm = "PBEWithMD5AndDES";
        
        PBEKeySpec	pbeKeySpec = new PBEKeySpec(passwd);
		SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(algorithm);
		SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);        
		
		Cipher cipher = Cipher.getInstance(algorithm);
		
		cipher.init(Cipher.ENCRYPT_MODE,pbeKey,pbeParamSpec);
		
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        System.out.println("input    : " + Hex.toHexString(input));

        byte[] output = cipher.doFinal(input);

        System.out.println("encrypted: " + Hex.toHexString(output));
        
        
        // Decrypt:

        cipher.init(Cipher.DECRYPT_MODE,pbeKey,pbeParamSpec);

        System.out.println("decrypted: "
                            + Hex.toHexString(cipher.doFinal(output)));
    }
}
