import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface Cracking {
    String D = "0123456789";
    String L = "abcdefghijklmnopqrstuvwxyz";
    String U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String A = D+L+U;
    int A_LEN = A.length();
    int D_LEN = D.length();
    int L_LEN = L.length();
    int U_LEN = U.length();
    static void crack(String dictFilename, String mask, String dataFilename)
            throws IOException, DecoderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Map<String,String> connectionData = parseFile(dataFilename);
        int[] maskValues = new int[mask.length()];
        findPassword(maskValues,dictFilename,connectionData,mask);
    }
    private static void findPassword(int[] maskValues,
                                     String dictFilename,
                                     Map<String, String> connectionData,
                                     String mask)
            throws IOException, DecoderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String passwordCur = getPasswordFromMask(maskValues,mask);
        Scanner dictionary = new Scanner(new File(dictFilename));
        String wordFromDict = getNextWordFromDict(dictionary);
        String finish = getPasswordFromMask(maskValues,mask);
        while(true){
            if(checkEqCountDec(connectionData,wordFromDict+passwordCur)){
                String passwordFound = new String(Hex.decodeHex(wordFromDict+passwordCur), StandardCharsets.US_ASCII);
                System.out.println("Password was found:: "+passwordFound);
                return;
            }
            passwordCur = getNextPassword(maskValues,mask);
            if(finish.equals(passwordCur)){
                if(dictionary.hasNext()){
                    wordFromDict = getNextWordFromDict(dictionary);
                    maskValues = new int[maskValues.length];
                    passwordCur = getPasswordFromMask(maskValues,mask);
                }
                else{
                    System.out.println("Password wasn't found");
                    return;
                }
            }

        }
    }
    private static String getNextWordFromDict(Scanner dictionary){
        return Hex.encodeHexString(dictionary.nextLine().getBytes(StandardCharsets.US_ASCII));
    }
    private static String getNextPassword(int[] passwordCur, String mask){
        int last = passwordCur.length-1;
        while (last>=0 && passwordCur[last] == getAlphLength(mask.substring(last,last+1))-1){
            passwordCur[last]=0;
            --last;
        }
        if(last>=0)
            passwordCur[last]+=1;
        return getPasswordFromMask(passwordCur,mask);
    }

    private static boolean checkEqCountDec(Map<String, String> connectionData, String passwordCur)
            throws DecoderException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String hashVal = connectionData.get("HashId");
        String algVal = connectionData.get("AlgId");
        String SKEYID = Generating.prf(passwordCur, connectionData.get("Ni")+ connectionData.get("Nr"), hashVal);
        String SKEYIDe = Generating.countSKEYIDe(SKEYID, hashVal);
        String iv = Generating.hashing(hashVal, connectionData.get("gx")+ connectionData.get("gy"));
        String key = Generating.countKeyForEncryption(SKEYIDe,hashVal,algVal);
        String decryptedData = Generating.gainEnc(connectionData.get("Ek"), key,iv, algVal,"dec");
        if(!decryptedData.equals("00")){
            String id = decryptedData.substring(0,8);
            String hashI = decryptedData.substring(8);
            String nonce = gainNonce(connectionData,id);
            String countHashI = Generating.prf(SKEYID,nonce,hashVal);
            return countHashI.equals(hashI);
        }
        return false;
    }

    private static String gainNonce(Map<String, String> data, String id){
        return data.get("gy")+
                data.get("gx")+
                data.get("Cr")+
                data.get("Ci")+
                data.get("SAi")+
                id;
    }
    private static String getPasswordFromMask(int[] maskValues, String mask){
        StringBuilder result = new StringBuilder();
        for(int i=0;i<maskValues.length;++i){
            result.append(getLetterFromAlphPos(mask.substring(i,i+1),maskValues[i]));
        }
        return Hex.encodeHexString(result.toString().getBytes(StandardCharsets.US_ASCII));
    }
    private static String getLetterFromAlphPos(String letter, int pos){
        switch (letter) {
            case "a":
                return A.substring(pos, pos + 1);
            case "d":
                return D.substring(pos, pos + 1);
            case "l":
                return L.substring(pos, pos + 1);
            case "u":
                return U.substring(pos, pos + 1);
        }
        throw new Error("Wrong letter in mask");
    }
    private static int getAlphLength(String letter){
        switch (letter) {
            case "a":
                return A_LEN;
            case "d":
                return D_LEN;
            case "l":
                return L_LEN;
            case "u":
                return U_LEN;
        }
        throw new Error("Wrong letter in mask");
    }
    private static Map<String,String> parseFile(String filename) throws IOException {
        Map<String,String> connectionData = new HashMap<>();
        Scanner scanner = new Scanner(new File(filename));
        String[] dataFromFile = scanner.nextLine().split("\\*");
        connectionData.put("Ci",dataFromFile[7]);
        connectionData.put("Cr",dataFromFile[8]);
        connectionData.put("Ni",dataFromFile[2]);
        connectionData.put("Nr",dataFromFile[3]);
        connectionData.put("gx",dataFromFile[4]);
        connectionData.put("gy",dataFromFile[5]);
        connectionData.put("gxy",dataFromFile[6]);
        connectionData.put("SAi",dataFromFile[9]);
        connectionData.put("Ek",dataFromFile[10]);
        if(dataFromFile[0].equals("1"))
            connectionData.put("HashId","md5");
        else
            connectionData.put("HashId","sha1");
        switch (dataFromFile[1]){
            case "5":
                connectionData.put("AlgId","3des");
                break;
            case "7":
                connectionData.put("AlgId","aes128");
                break;
            case "8":
                connectionData.put("AlgId","aes192");
                break;
            case "9":
                connectionData.put("AlgId","aes256");
                break;
        }
        return connectionData;
    }
}
