package webman;

import crypto.*;
import it.unisa.dia.gas.jpbc.Element;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WebmanUtils {
    
    public static class SystemParameters {
        private BilinearGroup bilinearGroup;
        private int N;
        private int n;
        private int B;
        private Element[] h;
        
        public SystemParameters(int N, int n, String propertiesFile) {
            this.N = N;
            this.n = n;
            this.B = (int) Math.ceil((double) N / n);
            this.bilinearGroup = new crypto.BilinearGroup(propertiesFile);
            this.h = new it.unisa.dia.gas.jpbc.Element[2 * n + 1];
            it.unisa.dia.gas.jpbc.Element g = bilinearGroup.getGenerator();
            it.unisa.dia.gas.jpbc.Element z = bilinearGroup.randomZr();
            for (int i = 1; i <= n; i++) {
                h[i] = g.powZn(z.pow(java.math.BigInteger.valueOf(i))).getImmutable();
            }
            for (int i = n + 2; i <= 2 * n; i++) {
                h[i] = g.powZn(z.pow(java.math.BigInteger.valueOf(i))).getImmutable();
            }
        }
        
        public BilinearGroup getBilinearGroup() { return bilinearGroup; }
        public int getN() { return N; }
        public int getn() { return n; }
        public int getB() { return B; }
        public Element[] getH() { return h; }
    }
    
    public static class PublicParameters {
        private Element[] C;
        
        public PublicParameters(int B, BilinearGroup bg) {
            this.C = new Element[B + 1];
            Element identity = bg.getG1().newOneElement();
            for (int i = 1; i <= B; i++) {
                C[i] = identity.duplicate().getImmutable();
            }
        }
        
        public Element[] getC() { return C; }
        public void updateC(int k, Element value) {
            C[k] = C[k].mul(value).getImmutable();
        }
    }
    
    public static class AuxiliaryParameters {
        private Map<Integer, Element> L;
        
        public AuxiliaryParameters(int N, BilinearGroup bg) {
            this.L = new HashMap<>();
            Element identity = bg.getG1().newOneElement();
            for (int i = 1; i <= N; i++) {
                L.put(i, identity.duplicate().getImmutable());
            }
        }
        
        public Map<Integer, Element> getL() { return L; }
        public Element getL(int id) { return L.get(id); }
        public void updateL(int id, Element value) {
            L.put(id, L.get(id).mul(value).getImmutable());
        }
    }
    
    public static class UserKeys {
        private int uid;
        private Element sk;
        private Element pk;
        private Element[] pap;
        
        public UserKeys(int uid, SystemParameters params) {
            this.uid = uid;
            BilinearGroup bg = params.getBilinearGroup();
            this.sk = bg.randomZr();
            
            int uPrime = (uid % params.getn()) + 1;
            this.pk = params.getH()[uPrime].powZn(sk).getImmutable();
            this.pap = new Element[params.getn() + 1];
            Element[] h = params.getH();
            int n = params.getn();
            for (int i = 1; i <= n; i++) {
                if (i != uPrime) {
                    int hIndex;
                    if (i < uPrime) {
                        hIndex = i + n;
                    } else {
                        hIndex = i;
                    }
                    if (hIndex > 0 && hIndex <= 2 * n && hIndex != n + 1 && h[hIndex] != null) {
                        pap[i] = h[hIndex].powZn(sk).getImmutable();
                    }
                }
            }
        }
        
        public int getUid() { return uid; }
        public Element getSk() { return sk; }
        public Element getPk() { return pk; }
        public Element[] getPap() { return pap; }
    }
    
    public static class ProcessedModel {
        private List<Integer> policyA, policyT, policyU;
        private Element[] caParams, ctParams, cuParams;
        private PaillierEncryption.PublicKey paillierPK;
        private SecretKey aesKey;
        private ChameleonHash.PublicKey chameleonPK;
        private byte[] encryptedModel;
        private Model model;
        private BigInteger ca6;
        private byte[] ct6;
        private PaillierEncryption.PrivateKey paillierSK;
        
        public ProcessedModel(List<Integer> policyA, List<Integer> policyT, List<Integer> policyU,
                            Element[] caParams, Element[] ctParams, Element[] cuParams,
                            PaillierEncryption.PublicKey paillierPK, SecretKey aesKey,
                            ChameleonHash.PublicKey chameleonPK, byte[] encryptedModel, Model model) {
            this.policyA = policyA;
            this.policyT = policyT;
            this.policyU = policyU;
            this.caParams = caParams;
            this.ctParams = ctParams;
            this.cuParams = cuParams;
            this.paillierPK = paillierPK;
            this.aesKey = aesKey;
            this.chameleonPK = chameleonPK;
            this.encryptedModel = encryptedModel;
            this.model = model;
            this.ca6 = null;
            this.ct6 = encryptedModel;
            this.paillierSK = null;
        }
        
        // 扩展构造函数，包含Webman算法参数
        public ProcessedModel(List<Integer> policyA, List<Integer> policyT, List<Integer> policyU,
                            Element[] caParams, Element[] ctParams, Element[] cuParams,
                            PaillierEncryption.PublicKey paillierPK, SecretKey aesKey,
                            ChameleonHash.PublicKey chameleonPK, byte[] encryptedModel, Model model,
                            BigInteger ca6, byte[] ct6, PaillierEncryption.PrivateKey paillierSK) {
            this.policyA = policyA;
            this.policyT = policyT;
            this.policyU = policyU;
            this.caParams = caParams;
            this.ctParams = ctParams;
            this.cuParams = cuParams;
            this.paillierPK = paillierPK;
            this.aesKey = aesKey;
            this.chameleonPK = chameleonPK;
            this.encryptedModel = encryptedModel;
            this.model = model;
            this.ca6 = ca6;
            this.ct6 = ct6;
            this.paillierSK = paillierSK;
        }
        
        // Getters
        public List<Integer> getPolicyA() { return policyA; }
        public List<Integer> getPolicyT() { return policyT; }
        public List<Integer> getPolicyU() { return policyU; }
        public Element[] getCaParams() { return caParams; }
        public Element[] getCtParams() { return ctParams; }
        public Element[] getCuParams() { return cuParams; }
        public PaillierEncryption.PublicKey getPaillierPK() { return paillierPK; }
        public SecretKey getAesKey() { return aesKey; }
        public ChameleonHash.PublicKey getChameleonPK() { return chameleonPK; }
        public byte[] getEncryptedModel() { return encryptedModel; }
        public Model getModel() { return model; }
        // 新增的getters
        public BigInteger getCa6() { return ca6; }
        public byte[] getCt6() { return ct6; }
        public PaillierEncryption.PrivateKey getPaillierSK() { return paillierSK; }
        
        // Setters for Webman算法参数
        public void setCa6(BigInteger ca6) { this.ca6 = ca6; }
        public void setCt6(byte[] ct6) { this.ct6 = ct6; }
        public void setPaillierSK(PaillierEncryption.PrivateKey paillierSK) { this.paillierSK = paillierSK; }
    }
    
    public static class RightsParameters {
        private Element[] availParams;
        private Element[] trainParams;
        private Element[] upgradeParams;
        
        public RightsParameters(Element[] availParams, Element[] trainParams, Element[] upgradeParams) {
            this.availParams = availParams;
            this.trainParams = trainParams;
            this.upgradeParams = upgradeParams;
        }
        
        public Element[] getAvailParams() { return availParams; }
        public Element[] getTrainParams() { return trainParams; }
        public Element[] getUpgradeParams() { return upgradeParams; }
    }
    
    public static int calculateK(int uid, int n) {
        return (int) Math.ceil((double) uid / n);
    }
    
    public static int calculateUPrime(int uid, int n) {
        return (uid % n) + 1;
    }
}