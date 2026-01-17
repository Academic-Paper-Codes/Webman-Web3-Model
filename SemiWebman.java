package webman;

import crypto.*;
import it.unisa.dia.gas.jpbc.Element;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class SemiWebman {
    private WebmanUtils.SystemParameters sysParams;
    private WebmanUtils.PublicParameters pubParams;
    private WebmanUtils.AuxiliaryParameters auxParams;

    public SemiWebman(int N, int n, String propertiesFile) {
        this.sysParams = new WebmanUtils.SystemParameters(N, n, propertiesFile);
        this.pubParams = new WebmanUtils.PublicParameters(sysParams.getB(), sysParams.getBilinearGroup());
        this.auxParams = new WebmanUtils.AuxiliaryParameters(N, sysParams.getBilinearGroup());
    }

    public static SetupResult setup(int lambda, int N, int n) {
        try {
            BilinearGroup bg = new BilinearGroup();
            int B = (int) Math.ceil((double) N / n);
            Element z = bg.randomZr();
            Element g = bg.getGenerator();
            Element[] h = new Element[2 * n + 1];
            for (int i = 1; i <= n; i++) {
                Element zPowI = z.duplicate();
                for (int j = 1; j < i; j++) {
                    zPowI = zPowI.mul(z);
                }
                h[i] = g.powZn(zPowI).getImmutable();
            }
            for (int i = n + 2; i <= 2 * n; i++) {
                Element zPowI = z.duplicate();
                for (int j = 1; j < i; j++) {
                    zPowI = zPowI.mul(z);
                }
                h[i] = g.powZn(zPowI).getImmutable();
            }
            CommonReferenceString crs = new CommonReferenceString(bg, N, B, n, h);
            Element[] pp = new Element[B + 1];
            Element identity = bg.getG1().newOneElement();
            for (int i = 1; i <= B; i++) {
                pp[i] = identity.duplicate().getImmutable();
            }
            Element[][] aux = new Element[N + 1][];
            for (int i = 1; i <= N; i++) {
                aux[i] = new Element[]{identity.duplicate().getImmutable()};
            }

            return new SetupResult(crs, pp, aux);
        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Setup algorithm failed", e);
        }
    }

    public WebmanUtils.UserKeys keyGen(int uid) {
        try {
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element[] h = sysParams.getH();
            int n = sysParams.getn();
            Element xid = bg.randomZr();
            int uPrime = (uid % n) + 1;
            Element skid = xid.duplicate().getImmutable();
            Element pkid = h[uPrime].powZn(xid).getImmutable();
            Element[] papid = new Element[n + 1];
            for (int i = 1; i <= n; i++) {
                if (i != uPrime) {
                    int hIndex;
                    if (i < uPrime) {
                        hIndex = i + n;
                    } else {
                        hIndex = i;
                    }
                    if (hIndex > 0 && hIndex <= 2 * n && hIndex != n + 1 && h[hIndex] != null) {
                        papid[i] = h[hIndex].powZn(xid).getImmutable();
                    }
                } else {
                    papid[i] = null;
                }
            }

            return new WebmanUtils.UserKeys(uid, skid, pkid, papid);

        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman KeyGen algorithm failed", e);
        }
    }

    public boolean register(WebmanUtils.UserKeys userKeys) {
        try {
            int uid = userKeys.getUid();
            Element pkid = userKeys.getPk();
            Element[] papid = userKeys.getPap();
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element[] h = sysParams.getH();
            int n = sysParams.getn();
            int N = sysParams.getN();
            if (uid < 1 || uid > N) {
                return false;
            }
            int uPrime = (uid % n) + 1;
            Element hn = h[n];
            Element g = bg.getGenerator();
            boolean verification = true;
            try {
                Element basePairing = bg.pairing(pkid, hn);
                for (int i = 1; i <= n; i++) {
                    if (i != uPrime && papid[i] != null) {
                        int hIndex;
                        if (i < uPrime) {
                            hIndex = i + n;
                        } else {
                            hIndex = i;
                        }
                        Element hTarget;
                        if (i == 1) {
                            hTarget = g;
                        } else if (i < uPrime) {
                            hTarget = h[i + n - 1];
                        } else {
                            hTarget = h[i - 1];
                        }
                        Element currentPairing = bg.pairing(papid[i], hTarget);
                        if (!currentPairing.isEqual(basePairing)) {
                            verification = false;
                            break;
                        }
                    }
                }

            } catch (Exception e) {
                verification = false;
            }
            if (!verification) {
                return false;
            }
            int k = (int) Math.ceil((double) uid / n);
            pubParams.updateC(k, pkid);
            int startRange = k * n - n + 1;
            int endRange = k * n;
            for (int i = startRange; i <= endRange; i++) {
                if (i != uid && i >= 1 && i <= N) {
                    int iPrime = (i % n) + 1;
                    if (papid[iPrime] != null) {
                        auxParams.updateL(i, papid[iPrime]);
                    }
                }
            }

            return true;

        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Register algorithm failed", e);
        }
    }
    public WebmanUtils.ProcessedModel process(List<Integer> policyA, List<Integer> policyT,
                                              List<Integer> policyU, Model model) {
        try {
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element g = bg.getGenerator();
            Element[] h = sysParams.getH();
            int n = sysParams.getn();

            int na = policyA.size();
            int nt = policyT.size();
            int nu = policyU.size();

            PaillierEncryption paillier = new PaillierEncryption(1024);
            PaillierEncryption.KeyPair paillierKeys = paillier.generateKeyPair();
            PaillierEncryption.PublicKey pka = paillierKeys.getPublicKey();
            PaillierEncryption.PrivateKey ska = paillierKeys.getPrivateKey();
            SecretKey skt = AESEncryption.generateKey();
            ChameleonHash chameleonHash = new ChameleonHash();
            ChameleonHash.KeyPair chameleonKeys = chameleonHash.generateKeyPair();
            ChameleonHash.PublicKey pku = chameleonKeys.getPublicKey();
            ChameleonHash.PrivateKey sku = chameleonKeys.getPrivateKey();
            Element ra1 = bg.randomZr();
            Element ra2 = bg.randomZr();
            Element[] ca1 = new Element[na];
            Element[] ca2 = new Element[na];
            Element[] ca4 = new Element[na];
            for (int i = 0; i < na; i++) {
                int uid = policyA.get(i);
                int k = (int) Math.ceil((double) uid / n);
                int uPrime = (uid % n) + 1;
                ca1[i] = pubParams.getC()[k].duplicate().getImmutable();
                int hIndex = n + 1 - uPrime;
                Element hElement = (hIndex > 0 && hIndex <= 2 * n && hIndex != n + 1) ? h[hIndex] : g;
                ca2[i] = bg.pairing(ca1[i], hElement).powZn(ra1).getImmutable();
                Element huPrime = (uPrime > 0 && uPrime <= 2 * n && uPrime != n + 1) ? h[uPrime] : g;
                Element pairingTerm = bg.pairing(huPrime, hElement).powZn(ra1);
                Element eggRa2 = bg.pairing(g, g).powZn(ra2);
                ca4[i] = pairingTerm.mul(eggRa2).getImmutable();
            }
            Element ca3 = g.powZn(ra1).getImmutable();
            Element eggRa2 = bg.pairing(g, g).powZn(ra2);
            byte[] hashRa2 = bg.hashToBytes(eggRa2);
            byte[] pkaBytes = pka.getN().toByteArray();
            byte[] ca5 = new byte[Math.max(hashRa2.length, pkaBytes.length)];
            for (int i = 0; i < ca5.length; i++) {
                byte aByte = (i < hashRa2.length) ? hashRa2[i] : 0;
                byte bByte = (i < pkaBytes.length) ? pkaBytes[i] : 0;
                ca5[i] = (byte) (aByte ^ bByte);
            }
            byte[] modelBytes = model.serialize();
            BigInteger modelValue = new BigInteger(1, modelBytes);
            BigInteger ca6 = paillier.encrypt(modelValue, pka);
            Element rt1 = bg.randomZr();
            Element rt2 = bg.randomZr();
            Element[] ct1 = new Element[nt];
            Element[] ct2 = new Element[nt];
            Element[] ct4 = new Element[nt];
            for (int i = 0; i < nt; i++) {
                int uid = policyT.get(i);
                int k = (int) Math.ceil((double) uid / n);
                int uPrime = (uid % n) + 1;
                ct1[i] = pubParams.getC()[k].duplicate().getImmutable();
                int hIndex = n + 1 - uPrime;
                Element hElement = (hIndex > 0 && hIndex <= 2 * n && hIndex != n + 1) ? h[hIndex] : g;
                ct2[i] = bg.pairing(ct1[i], hElement).powZn(rt1).getImmutable();

                Element huPrime = (uPrime > 0 && uPrime <= 2 * n && uPrime != n + 1) ? h[uPrime] : g;
                Element pairingTerm = bg.pairing(huPrime, hElement).powZn(rt1);
                Element eggRt2 = bg.pairing(g, g).powZn(rt2);
                ct4[i] = pairingTerm.mul(eggRt2).getImmutable();
            }
            Element ct3 = g.powZn(rt1).getImmutable();
            Element eggRt2 = bg.pairing(g, g).powZn(rt2);
            byte[] hashRt2 = bg.hashToBytes(eggRt2);
            byte[] sktBytes = skt.getEncoded();
            byte[] ct5 = new byte[Math.max(hashRt2.length, sktBytes.length)];
            for (int i = 0; i < ct5.length; i++) {
                byte aByte = (i < hashRt2.length) ? hashRt2[i] : 0;
                byte bByte = (i < sktBytes.length) ? sktBytes[i] : 0;
                ct5[i] = (byte) (aByte ^ bByte);
            }
            byte[] ct6 = AESEncryption.encrypt(modelBytes, skt);
            Element ru1 = bg.randomZr();
            Element ru2 = bg.randomZr();
            Element[] cu1 = new Element[nu];
            Element[] cu2 = new Element[nu];
            Element[] cu4 = new Element[nu];
            for (int i = 0; i < nu; i++) {
                int uid = policyU.get(i);
                int k = (int) Math.ceil((double) uid / n);
                int uPrime = (uid % n) + 1;
                cu1[i] = pubParams.getC()[k].duplicate().getImmutable();
                int hIndex = n + 1 - uPrime;
                Element hElement = (hIndex > 0 && hIndex <= 2 * n && hIndex != n + 1) ? h[hIndex] : g;
                cu2[i] = bg.pairing(cu1[i], hElement).powZn(ru1).getImmutable();
                Element huPrime = (uPrime > 0 && uPrime <= 2 * n && uPrime != n + 1) ? h[uPrime] : g;
                Element pairingTerm = bg.pairing(huPrime, hElement).powZn(ru1);
                Element eggRu2 = bg.pairing(g, g).powZn(ru2);
                cu4[i] = pairingTerm.mul(eggRu2).getImmutable();
            }
            Element cu3 = g.powZn(ru1).getImmutable();
            Element eggRu2 = bg.pairing(g, g).powZn(ru2);
            byte[] hashRu2 = bg.hashToBytes(eggRu2);
            byte[] skuBytes = sku.getX().toByteArray();
            byte[] cu5 = new byte[Math.max(hashRu2.length, skuBytes.length)];
            for (int i = 0; i < cu5.length; i++) {
                byte aByte = (i < hashRu2.length) ? hashRu2[i] : 0;
                byte bByte = (i < skuBytes.length) ? skuBytes[i] : 0;
                cu5[i] = (byte) (aByte ^ bByte);
            }
            byte[] combinedData = concatenateBytes(ca6.toByteArray(), ct6);
            ChameleonHash.HashResult cu6 = chameleonHash.hash(combinedData, pku);
            Element[] caParams = new Element[6];
            caParams[0] = ca1[0];
            caParams[1] = ca2[0];
            caParams[2] = ca3;
            caParams[3] = ca4[0];
            caParams[4] = bg.hashToZr(ca5);
            caParams[5] = bg.hashToZr(ca6.toByteArray());
            Element[] ctParams = new Element[6];
            ctParams[0] = ct1[0];
            ctParams[1] = ct2[0];
            ctParams[2] = ct3;
            ctParams[3] = ct4[0];
            ctParams[4] = bg.hashToZr(ct5);
            ctParams[5] = bg.hashToZr(ct6);
            Element[] cuParams = new Element[6];
            cuParams[0] = cu1[0];
            cuParams[1] = cu2[0];
            cuParams[2] = cu3;
            cuParams[3] = cu4[0];
            cuParams[4] = bg.hashToZr(cu5);
            cuParams[5] = bg.hashToZr(cu6.getHash().toByteArray());
            return new WebmanUtils.ProcessedModel(
                    policyA, policyT, policyU,
                    caParams, ctParams, cuParams,
                    pka, skt, pku, ct6, model, ca6, ct6, ska
            );
        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Process algorithm failed", e);
        }
    }
    
    public WebmanUtils.RightsParameters check(int uid, WebmanUtils.ProcessedModel processedModel) {
        Element[] Ra = null;
        Element[] Rt = null;
        Element[] Ru = null;
        if (processedModel.getPolicyA() != null && processedModel.getPolicyA().contains(uid)) {
            Ra = extractUserParams(uid, processedModel.getPolicyA(), processedModel.getCaParams());
        }
        if (processedModel.getPolicyT() != null && processedModel.getPolicyT().contains(uid)) {
            Rt = extractUserParams(uid, processedModel.getPolicyT(), processedModel.getCtParams());
        }
        if (processedModel.getPolicyU() != null && processedModel.getPolicyU().contains(uid)) {
            Ru = extractUserParams(uid, processedModel.getPolicyU(), processedModel.getCuParams());
        }
        return new WebmanUtils.RightsParameters(Ra, Rt, Ru);
    }
    
    public Element update(int uid, int k) {
        return auxParams.getL(uid);
    }
    
    public double[] avail(Element skid, Element Lid, Element[] Ra, double[] m,
                          WebmanUtils.ProcessedModel processedModel) {
        try {
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element g = bg.getGenerator();
            Element ca1j = Ra[0];
            Element ca2j = Ra[1];
            Element ca3 = Ra[2];
            Element ca4j = Ra[3];
            Element ca5 = Ra[4];
            Element denomTermPairing = bg.pairing(Lid, ca3).invert();
            Element denomTerm = denomTermPairing.mul(ca2j);
            Element denomPowered = denomTerm.powZn(skid.invert());
            Element ra2 = ca4j.div(denomPowered);

            Element eggRa2 = bg.pairing(g, g).powZn(ra2);
            byte[] hashEggRa2 = bg.hashToBytes(eggRa2);
            byte[] ca5Bytes = ca5.toBytes();
            byte[] pkaBytes = new byte[Math.max(hashEggRa2.length, ca5Bytes.length)];
            for (int i = 0; i < pkaBytes.length; i++) {
                byte aByte = (i < ca5Bytes.length) ? ca5Bytes[i] : 0;
                byte bByte = (i < hashEggRa2.length) ? hashEggRa2[i] : 0;
                pkaBytes[i] = (byte) (aByte ^ bByte);
            }
            BigInteger pkaN = new BigInteger(1, pkaBytes);
            BigInteger pkaG = pkaN.add(BigInteger.ONE);
            PaillierEncryption.PublicKey pka = new PaillierEncryption.PublicKey(pkaN, pkaG);
            PaillierEncryption paillier = new PaillierEncryption(1024);
            BigInteger encodedInput = HomomorphicMLPEvaluator.encodeInput(m);
            BigInteger Cm = paillier.encrypt(encodedInput, pka);
            BigInteger ca6 = processedModel.getCa6();
            if (ca6 == null) {
                throw new RuntimeException("ca,6 not found in processed model");
            }
            BigInteger ESR = HomomorphicMLPEvaluator.homomorphicEvaluate(ca6, Cm, pka, paillier);
            PaillierEncryption.PrivateKey ska = processedModel.getPaillierSK();
            if (ska == null) {
                throw new RuntimeException("Paillier private key not found in processed model");
            }
            BigInteger decryptedResult = paillier.decrypt(ESR, ska);
            double prediction = HomomorphicMLPEvaluator.decodeResult(decryptedResult);
            return new double[]{prediction};
        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Avail algorithm failed", e);
        }
    }

    public byte[] train(Element skid, Element Lid, Element[] Rt,
                        WebmanUtils.ProcessedModel processedModel) {
        try {
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element g = bg.getGenerator();
            Element ct1j = Rt[0];
            Element ct2j = Rt[1];
            Element ct3 = Rt[2];
            Element ct4j = Rt[3];
            Element ct5 = Rt[4];
            Element denomTermPairing = bg.pairing(Lid, ct3).invert();
            Element denomTerm = denomTermPairing.mul(ct2j);
            Element denomPowered = denomTerm.powZn(skid.invert());
            Element rt2 = ct4j.div(denomPowered);
            Element eggRt2 = bg.pairing(g, g).powZn(rt2);
            byte[] hashEggRt2 = bg.hashToBytes(eggRt2);
            byte[] ct5Bytes = ct5.toBytes();
            int keyLen = 32;
            byte[] xorSourceA = new byte[keyLen];
            byte[] xorSourceB = new byte[keyLen];
            System.arraycopy(ct5Bytes, 0, xorSourceA, 0, Math.min(ct5Bytes.length, keyLen));
            System.arraycopy(hashEggRt2, 0, xorSourceB, 0, Math.min(hashEggRt2.length, keyLen));
            byte[] sktBytes = new byte[keyLen];
            for (int i = 0; i < keyLen; i++) {
                sktBytes[i] = (byte) (xorSourceA[i] ^ xorSourceB[i]);
            }
            SecretKey skt = AESEncryption.bytesToKey(sktBytes);
            byte[] ct6 = processedModel.getCt6();
            if (ct6 == null) {
                throw new RuntimeException("ct,6 is null in ProcessedModel");
            }
            byte[] modelBytes = AESEncryption.decrypt(ct6, skt);
            byte[] trainedModelBytes = modelBytes;
            byte[] cPrimeM = AESEncryption.encrypt(trainedModelBytes, skt);
            return cPrimeM;

        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Train algorithm failed", e);
        }
    }

    public WebmanUtils.ProcessedModel upgrade(Element skid, Element Lid, Element[] Ru,
                                              List<byte[]> trainedModels,
                                              WebmanUtils.ProcessedModel processedModel) {
        try {
            BilinearGroup bg = sysParams.getBilinearGroup();
            Element g = bg.getGenerator();
            Element cu1j = Ru[0];
            Element cu2j = Ru[1];
            Element cu3 = Ru[2];
            Element cu4j = Ru[3];
            Element cu5 = Ru[4];
            Element denomTermPairing = bg.pairing(Lid, cu3).invert();
            Element denomTerm = denomTermPairing.mul(cu2j);
            Element denomPowered = denomTerm.powZn(skid.invert());
            Element ru2 = cu4j.div(denomPowered);
            Element eggRu2 = bg.pairing(g, g).powZn(ru2);
            byte[] hashEggRu2 = bg.hashToBytes(eggRu2);
            byte[] cu5Bytes = cu5.toBytes();
            byte[] skuBytes = new byte[Math.max(hashEggRu2.length, cu5Bytes.length)];
            for (int i = 0; i < skuBytes.length; i++) {
                byte aByte = (i < cu5Bytes.length) ? cu5Bytes[i] : 0;
                byte bByte = (i < hashEggRu2.length) ? hashEggRu2[i] : 0;
                skuBytes[i] = (byte) (aByte ^ bByte);
            }
            BigInteger skuValue = new BigInteger(1, skuBytes);
            BigInteger p = BigInteger.valueOf(2).pow(1024).subtract(BigInteger.ONE);
            BigInteger q = BigInteger.valueOf(2).pow(160).subtract(BigInteger.ONE);
            ChameleonHash.PrivateKey sku = new ChameleonHash.PrivateKey(skuValue, p, q);
            SecretKey skt = processedModel.getAesKey();
            List<Model> plaintextModels = new ArrayList<>();
            for (byte[] encryptedModel : trainedModels) {
                byte[] decryptedBytes = AESEncryption.decrypt(encryptedModel, skt);
                Model model = Model.deserialize(decryptedBytes);
                plaintextModels.add(model);
            }
            Model aggregatedModel = aggregateModels(plaintextModels);
            byte[] aggregatedModelBytes = aggregatedModel.serialize();
            byte[] newCt6 = AESEncryption.encrypt(aggregatedModelBytes, skt);
            PaillierEncryption.PublicKey pka = processedModel.getPaillierPK();
            PaillierEncryption paillier = new PaillierEncryption(1024);
            BigInteger modelValue = new BigInteger(1, aggregatedModelBytes);
            BigInteger newCa6 = paillier.encrypt(modelValue, pka);
            byte[] combinedData = concatenateBytes(newCa6.toByteArray(), newCt6);
            ChameleonHash chameleonHash = new ChameleonHash();
            ChameleonHash.PublicKey pku = processedModel.getChameleonPK();
            ChameleonHash.HashResult newHashResult = chameleonHash.hash(combinedData, pku);
            List<Integer> emptyPolicy = new ArrayList<>();
            Element[] emptyParams = new Element[6];
            return new WebmanUtils.ProcessedModel(
                    emptyPolicy, emptyPolicy, emptyPolicy,
                    emptyParams, emptyParams, emptyParams,
                    pka, skt, pku, newCt6, aggregatedModel, newCa6, newCt6,
                    processedModel.getPaillierSK()
            );
        } catch (Exception e) {
            throw new RuntimeException("Semi-Webman Upgrade algorithm failed", e);
        }
    }
    public static class CommonReferenceString {
        public final BilinearGroup bilinearGroup;
        public final int N;
        public final int B;
        public final int n;
        public final Element[] h;

        public CommonReferenceString(BilinearGroup bg, int N, int B, int n, Element[] h) {
            this.bilinearGroup = bg;
            this.N = N;
            this.B = B;
            this.n = n;
            this.h = h;
        }
    }

    public static class SetupResult {
        public final CommonReferenceString crs;
        public final Element[] pp;
        public final Element[][] aux;

        public SetupResult(CommonReferenceString crs, Element[] pp, Element[][] aux) {
            this.crs = crs;
            this.pp = pp;
            this.aux = aux;
        }
    }

    public WebmanUtils.SystemParameters getSystemParameters() {
        return sysParams;
    }

    public WebmanUtils.PublicParameters getPublicParameters() {
        return pubParams;
    }

    public WebmanUtils.AuxiliaryParameters getAuxiliaryParameters() {
        return auxParams;
    }
}