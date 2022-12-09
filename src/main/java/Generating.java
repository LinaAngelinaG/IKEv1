import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.util.Map;

public interface Generating {
    final static String charToDivide = "*";
    final static Map<String,Integer> IDS = new HashMap<>(){
        {
            IDS.put("md5",1);
            IDS.put("sha1",2);
            IDS.put("3des",5);
            IDS.put("aes128",7);
            IDS.put("aes192",8);
            IDS.put("aes256",9);
        }
    };
    final static Map<String,Integer> BYTES_IN_KEY = new HashMap<>(){
        {
            IDS.put("3des",8);
            IDS.put("aes128",16);
            IDS.put("aes192",24);
            IDS.put("aes256",32);
        }
    };
    final static Map<String,String> FIXED_DATA = new HashMap<>(){
        {
            FIXED_DATA.put("Ci","d6d4206808782d9a");
            FIXED_DATA.put("Cr","82d15be76515786c");
            FIXED_DATA.put("Ni","65531a662865c353086a3c17d51d64fc29f5cde3de1d3bf1dc1dfe32bf77f36e");
            FIXED_DATA.put("Nr","b4daa9232e3437cf3b2cc5e6aeddb3b789231a47bef29d6e7382462480595db5");
            FIXED_DATA.put("gx","867729b9e366ce82845fbe9e9a9aa790d8c7e6b0ab9a342e51bf97336ab011243fcdcee500d677456201acb893b4f0b25511b4bbe16fc7999dce11c15e4e9f702b4d7fdaf508f68c1dfeb418a2cd3f61beb74118b1484d402fded7d0613853f5b5a12027dcec5135bf4581658bd06dbfeb2dccb9217b474aad03074ef3fc005a");
            FIXED_DATA.put("gy","2dc4685effd8b4e7a8ae5580ecbee1740ea76ebe68821bd26f2ce7eddf827d1ab19d2261a62ae611abf8409ff2b9012895a5d45735523ed65f69625fbfb108d03782b3e1eec7d3c6fa9f2cf89e2bc5c48e32bc0e2fca28fbaf441247538ec83beb79f70c3bd5e06794b7e843d9e9ef11e9f5c578b656a0cf0a51fa84f00f8a7a");
            FIXED_DATA.put("gxy","4169e27b7236aa159e5f036f953f52c7ead117651ab7727a99e7305287f3f975f282e019bfc0a893a55379b51cb3de3df16ade45e9b5c3829f2284ef1b4bc111370d63d20a53b2849c3ee20662db882bf8192a28bedb7ae50cb019e35356d234a5ccf27880311d14a7580640233935f2a6e7264e389c0ae17beb364528af9f9f");
            FIXED_DATA.put("SAi","00000001000000010000002c000100010000002400010000800b0001800c0e1080010007800e0080800200028003000180040002");
            FIXED_DATA.put("IDi","232d0111");
        }
    };
    public default void generate(String filename, String hashVal, String algVal, String password)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, DecoderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        PrintWriter file = getFileStream(hashVal,algVal,password);
        if(filename.isEmpty()){
            generateWithDefaultData(file, hashVal, algVal, password);
            return;
        }
        generateWithDataFromFile(file, filename, hashVal, algVal, password);
    }
    private void generateWithDefaultData(PrintWriter file, String hashVal, String algVal, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            DecoderException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        String prefix = gainPrefix(hashVal,algVal);
        file.print(prefix);
        file.print(calculateEk(password,hashVal,algVal));
    }

    private String calculateEk(String password, String hashVal, String algVal)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        String SKEYID = prf(password, FIXED_DATA.get("Ni")+ FIXED_DATA.get("Nr"), hashVal);
        String nonce = gainNonce();
        String hashI = prf(SKEYID,nonce,hashVal);
        String SKEYIDe = countSKEYIDe(SKEYID, hashVal);
        String iv = prf(SKEYIDe, FIXED_DATA.get("gx")+ FIXED_DATA.get("gy"), hashVal);
        String key = countKeyForEncryption(SKEYIDe,hashVal,algVal);
        String Ek = gainEnc(FIXED_DATA.get("IDi")+hashI,key,iv,algVal);
        return Ek;
    }

    private String countKeyForEncryption(String skeyiDe, String hashVal, String encVal)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
        String k1 = prf(skeyiDe,"00",hashVal);
        String k2 = prf(skeyiDe, k1,hashVal);
        String k3 = prf(skeyiDe, k2, hashVal);
        return (k1+k2+k3).substring(0,BYTES_IN_KEY.get(encVal));
    }

    private String countSKEYIDe(String SKEYID, String hashVal)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
        String s = FIXED_DATA.get("gxy")+ FIXED_DATA.get("Ci")+ FIXED_DATA.get("Cr");
        String SKd = prf(SKEYID, Hex.decodeHex(s+"00"), hashVal);
        String SKa = prf(SKEYID, Hex.decodeHex(SKd+s+"01"), hashVal);
        return prf(SKEYID, Hex.decodeHex(SKa+s+"02"), hashVal);
    }

    private String prf(byte[] key, byte[] text, String hashVal)
            throws NoSuchAlgorithmException, InvalidKeyException {
       return countPRF(key,text,hashVal);
    }
    private String prf(String key, byte[] text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] keyn = Hex.decodeHex(key);
        return countPRF(keyn,text,hashVal);
    }
    private String prf(byte[] key, String text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] textn = Hex.decodeHex(text);
        return countPRF(key,textn,hashVal);
    }
    private String prf(String key, String text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] keyn = Hex.decodeHex(key);
        byte[] textn = Hex.decodeHex(text);
        return countPRF(keyn,textn,hashVal);
    }
    private String countPRF(byte[] key, byte[] text, String hashVal)
            throws NoSuchAlgorithmException, InvalidKeyException {
        if(hashVal.equals("md5")){
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacMD5");
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(secretKeySpec);
            return Hex.encodeHexString(mac.doFinal(text));
        }
        else{
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKeySpec);
            return Hex.encodeHexString(mac.doFinal(text));
        }
    }
    private String gainNonce(){
        return FIXED_DATA.get("gy")+
                FIXED_DATA.get("gx")+
                FIXED_DATA.get("Cr")+
                FIXED_DATA.get("Ci")+
                FIXED_DATA.get("SAi")+
                FIXED_DATA.get("IDi");
    }
    private String gainPrefix(String hashVal, String algVal){
        return IDS.get(hashVal)+
                charToDivide+
                IDS.get(algVal)+
                charToDivide+
                FIXED_DATA.get("Ni")+
                charToDivide+
                FIXED_DATA.get("Nr")+
                charToDivide+
                FIXED_DATA.get("gx")+
                charToDivide+
                FIXED_DATA.get("gy")+
                charToDivide+
                FIXED_DATA.get("gxy")+
                charToDivide+
                FIXED_DATA.get("Ci")+
                charToDivide+
                FIXED_DATA.get("Cr")+
                charToDivide+
                FIXED_DATA.get("SAi")+
                charToDivide;
    }
    private void generateWithDataFromFile(PrintWriter file, String filename, String hashVal, String algVal, String password){

    }
    private String gainEnc(String data, String password, String iv, String algo)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException, DecoderException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        IvParameterSpec ivSpec = new IvParameterSpec(Hex.decodeHex(iv));
        SecretKeySpec key;
        Cipher cipher;
        if(algo.equals("des3")){
            key = new SecretKeySpec(Hex.decodeHex(password), "DES");
            cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        }
        else{
            key = new SecretKeySpec(Hex.decodeHex(password), "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);
        return Hex.encodeHexString(cipher.doFinal(Hex.decodeHex(data)));
    }
    private PrintWriter getFileStream(String hashVal, String algVal, String password) throws IOException {
        StringBuilder name = new StringBuilder();
        name.append(hashVal);
        name.append("_");
        name.append(algVal);
        name.append("_");
        name.append(password);
        name.append(".txt");
        PrintWriter file = new PrintWriter(name.toString(), StandardCharsets.US_ASCII);
        return file;
    }
}