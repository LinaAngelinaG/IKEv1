import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.util.Map;

public interface Generating {
    String charToDivide = "*";
    Map<String,Integer> IDS = new HashMap(){
        {
            put("md5",1);
            put("sha1",2);
            put("3des",5);
            put("aes128",7);
            put("aes192",8);
            put("aes256",9);
        }
    };
    Map<String,Integer> BYTES_IN_KEY = new HashMap(){
        {
            put("3des",8);
            put("aes128",16);
            put("aes192",24);
            put("aes256",32);
        }
    };
    public Map<String,String> FIXED_DATA = new HashMap<>(){
        {
            put("Ci","d6d4206808782d9a");
            put("Cr","82d15be76515786c");
            put("Ni","65531a662865c353086a3c17d51d64fc29f5cde3de1d3bf1dc1dfe32bf77f36e");
            put("Nr","b4daa9232e3437cf3b2cc5e6aeddb3b789231a47bef29d6e7382462480595db5");
            put("gx","867729b9e366ce82845fbe9e9a9aa790d8c7e6b0ab9a342e51bf97336ab011243fcdcee500d677456201acb893b4f0b25511b4bbe16fc7999dce11c15e4e9f702b4d7fdaf508f68c1dfeb418a2cd3f61beb74118b1484d402fded7d0613853f5b5a12027dcec5135bf4581658bd06dbfeb2dccb9217b474aad03074ef3fc005a");
            put("gy","2dc4685effd8b4e7a8ae5580ecbee1740ea76ebe68821bd26f2ce7eddf827d1ab19d2261a62ae611abf8409ff2b9012895a5d45735523ed65f69625fbfb108d03782b3e1eec7d3c6fa9f2cf89e2bc5c48e32bc0e2fca28fbaf441247538ec83beb79f70c3bd5e06794b7e843d9e9ef11e9f5c578b656a0cf0a51fa84f00f8a7a");
            put("gxy","4169e27b7236aa159e5f036f953f52c7ead117651ab7727a99e7305287f3f975f282e019bfc0a893a55379b51cb3de3df16ade45e9b5c3829f2284ef1b4bc111370d63d20a53b2849c3ee20662db882bf8192a28bedb7ae50cb019e35356d234a5ccf27880311d14a7580640233935f2a6e7264e389c0ae17beb364528af9f9f");
            put("SAi","00000001000000010000002c000100010000002400010000800b0001800c0e1080010007800e0080800200028003000180040002");
            put("IDi","01110000c0a80c02");
        }
    };
    public static void generate(String filename, String hashVal, String algVal, String password)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            DecoderException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        PrintWriter file = getFileStream(hashVal,algVal,password);
        if(filename.isEmpty()){
            generateWithDefaultData(file, hashVal, algVal, password);
            return;
        }
        generateWithDataFromFile(file, filename, hashVal, algVal, password);
    }
    private static void generateWithDefaultData(PrintWriter file, String hashVal, String algVal, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            DecoderException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        String prefix = gainPrefix(hashVal,algVal);
        file.print(prefix);
        String ek = calculateEk(password,hashVal,algVal);
        file.print(ek);
        System.out.println("EK:  "+ek);
        System.out.println(gainEnc(ek,"81410834f8022cede3140ef8a0f18b63","0e7ea0ad0964efab5e7ab6fc9c8e493a",algVal,"dec"));
        file.close();
    }
    private static String calculateEk(String password, String hashVal, String algVal)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        String SKEYID = prf(password, FIXED_DATA.get("Ni")+ FIXED_DATA.get("Nr"), hashVal);
        String nonce = gainNonce();
        String hashI = prf(SKEYID,nonce,hashVal);
        String SKEYIDe = countSKEYIDe(SKEYID, hashVal,FIXED_DATA.get("gxy")+ FIXED_DATA.get("Ci")+ FIXED_DATA.get("Cr"));
        String iv = hashing(hashVal,FIXED_DATA.get("gx")+ FIXED_DATA.get("gy"));
        iv = algVal.equals("3des")? iv.substring(0,16):iv.substring(0,32);
        String key = countKeyForEncryption(SKEYIDe,hashVal,algVal);
        System.out.println("KEY::   "+key);
        System.out.println("IV::   "+iv);
        return gainEnc(FIXED_DATA.get("IDi")+hashI,key,iv,algVal,"enc");
    }
    static String countKeyForEncryption(String skeyiDe, String hashVal, String encVal)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
        String k1 = prf(skeyiDe,"00",hashVal);
        String k2 = prf(skeyiDe, k1,hashVal);
        return (k1+k2).substring(0,BYTES_IN_KEY.get(encVal)*2);
    }
    static String countSKEYIDe(String SKEYID, String hashVal, String nonce)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
        String SKd = prf(SKEYID, Hex.decodeHex(nonce+"00"), hashVal);
        String SKa = prf(SKEYID, Hex.decodeHex(SKd+nonce+"01"), hashVal);
        return prf(SKEYID, Hex.decodeHex(SKa+nonce+"02"), hashVal);
    }
    static String prf(byte[] key, byte[] text, String hashVal)
            throws NoSuchAlgorithmException, InvalidKeyException {
       return countPRF(key,text,hashVal);
    }
    static String prf(String key, byte[] text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] keyn = Hex.decodeHex(key);
        return countPRF(keyn,text,hashVal);
    }
    static String prf(byte[] key, String text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] textn = Hex.decodeHex(text);
        return countPRF(key,textn,hashVal);
    }
    static String prf(String key, String text, String hashVal)
            throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        byte[] keyn = Hex.decodeHex(key);
        byte[] textn = Hex.decodeHex(text);
        return countPRF(keyn,textn,hashVal);
    }
    static String hashing(String algo, String input) throws DecoderException, NoSuchAlgorithmException {
        MessageDigest dig;
        if(algo.equals("md5"))
            dig = MessageDigest.getInstance("MD5");
        else
            dig = MessageDigest.getInstance("SHA1");
        return Hex.encodeHexString(dig.digest());
    }
    private static String countPRF(byte[] key, byte[] text, String hashVal)
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
    private static String gainNonce(){
        return FIXED_DATA.get("gx")+
                FIXED_DATA.get("gy")+
                FIXED_DATA.get("Ci")+
                FIXED_DATA.get("Cr")+
                FIXED_DATA.get("SAi")+
                FIXED_DATA.get("IDi");
    }
    private static String gainPrefix(String hashVal, String algVal){
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
    private static void generateWithDataFromFile(PrintWriter file, String filename, String hashVal, String algVal, String password){
    }
    static String gainEnc(String data, String password, String iv, String algo, String mode)
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
        if(mode.equals("enc"))
            cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);
        else
            cipher.init(Cipher.DECRYPT_MODE,key,ivSpec);
        try{
            return Hex.encodeHexString(cipher.doFinal(Hex.decodeHex(data)));
        }catch (BadPaddingException exception){
            return "00";
        }
    }
    private static PrintWriter getFileStream(String hashVal, String algVal, String password) throws IOException {
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