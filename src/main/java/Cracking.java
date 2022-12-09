import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public interface Cracking {
    final static String D = "0123456789";
    final static String L = "abcdefghijklmnopqrstuvwxyz";
    final static String U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    final static String A = D+L+U;
    final static int A_LEN = A.length();
    final static int D_LEN = D.length();
    final static int L_LEN = L.length();
    final static int U_LEN = U.length();

    public default void crack(String dictFilename, String mask, String dataFilename) throws IOException {
        Map<String,String> connectionData = parseFile(dataFilename);
        int[] maskValues = new int[mask.length()];
        findPassword(maskValues,dictFilename,connectionData,mask);
    }

    private void findPassword(int[] maskValues,
                              String dictFilename,
                              Map<String, String> connectionData,
                              String mask) throws IOException {
        String passwordCur = getPasswordFromMask(maskValues,mask);
        String passwordNext = getNextPassword(maskValues, mask);
        Scanner dictionary = new Scanner(Path.of(dictFilename),StandardCharsets.US_ASCII);
        String wordFromDict = dictionary.nextLine();
        maskValues[maskValues.length-1] = 1;
        String finish = getPasswordFromMask(maskValues,mask);
        maskValues[maskValues.length-1] = 0;

        while(true){
            if(checkEqCountDec(connectionData,passwordCur)){
                System.out.println("Password was found:: "+passwordCur);
                return;
            }
            passwordCur = passwordNext;
            passwordNext = getNextPassword(maskValues,mask);
            if(finish.equals(passwordNext)){
                System.out.println("Password wasn't found");
                return;
            }
        }
    }

    private String getNextPassword(int[] passwordCur, String mask){
//        let = len(password) - 1
//        pas = password.copy()
//        while let >= 0 and pas[let] == get_alph_len(mask[let]) - 1:
//        pas[let] = 0
//        let -= 1
//        if let >= 0:
//        pas[let] += 1
//        return pas
        int last = passwordCur.length;
        while (last>=0 && passwordCur[last] == getAlphLength(mask.substring(last,last+1))-1){
            passwordCur[last]=0;
            --last;
        }
        if(last>=0)
            passwordCur[last]+=1;
        
    }

    private boolean checkEqCountDec(Map<String, String> connectionData, String passwordCur){

    }

    private String getPasswordFromMask(int[] maskValues, String mask){
        StringBuilder result = new StringBuilder();
        for(int i=0;i<maskValues.length;++i){
            result.append(getLetterFromAlphPos(mask.substring(i,i+1),maskValues[i]));
        }
        return result.toString();
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
    private Map<String,String> parseFile(String filename) throws IOException {
        Map<String,String> connectionData = new HashMap<>();
        Scanner scanner = new Scanner(Path.of(filename), StandardCharsets.US_ASCII);
        String[] dataFromFile = scanner.next().split("/*");
        connectionData.put("Ci",dataFromFile[7]);
        connectionData.put("Cr",dataFromFile[8]);
        connectionData.put("Ni",dataFromFile[2]);
        connectionData.put("Nr",dataFromFile[3]);
        connectionData.put("gx",dataFromFile[4]);
        connectionData.put("gy",dataFromFile[5]);
        connectionData.put("gxy",dataFromFile[6]);
        connectionData.put("SAi",dataFromFile[9]);
        connectionData.put("Ek",dataFromFile[10]);
        connectionData.put("HashId",dataFromFile[0]);
        connectionData.put("AldId",dataFromFile[1]);
        return connectionData;
    }
}
