import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws DecoderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String s = "hjgfd"+"fkdjh";
        String s2 = "vd";
        String s3 = s +s2;
        //System.out.println(s3);
        String pass = Hex.encodeHexString("ad199".getBytes(StandardCharsets.US_ASCII));
        System.out.println(pass);
        Generating.generate("","md5","aes128",pass);
        Cracking.crack("dict.txt","ddd","md5_aes128_6164313939.txt");
    }
}
