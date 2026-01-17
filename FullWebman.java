package webman;

import crypto.*;
import it.unisa.dia.gas.jpbc.Element;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FullWebman extends SemiWebman {
    private int numServers;
    private Map<Integer, BigInteger> serverKeyShares;
    private List<Integer> serverIds;

    public FullWebman(int N, int n, int numServers, String propertiesFile) {
        super(N, n, propertiesFile);
        this.numServers = numServers;
        this.serverKeyShares = new HashMap<>();
        this.serverIds = new ArrayList<>();
        for (int i = 1; i <= numServers; i++) {
            serverIds.add(i);
        }
    }

    public static FullWebmanSetupResult setup(int lambda, int N, int n, int numServers) {
        try {
            SemiWebman.SetupResult semiResult = SemiWebman.setup(lambda, N, n);
            if (numServers < 2) {
                throw new IllegalArgumentException("Full-Webman requires at least 2 servers for collaboration");
            }
            List<Integer> serverIds = new ArrayList<>();
            for (int i = 1; i <= numServers; i++) {
                serverIds.add(i);
            }
            Map<Integer, BigInteger> serverSharesMap = new HashMap<>();
            int threshold = numServers / 2 + 1;

            return new FullWebmanSetupResult(
                    semiResult.crs,
                    semiResult.pp,
                    semiResult.aux,
                    numServers,
                    serverIds,
                    serverSharesMap,
                    threshold
            );

        } catch (Exception e) {
            throw new RuntimeException("Full-Webman Setup algorithm failed", e);
        }
    }

    public DistributedProcessedModel process(List<Integer> policyA, List<Integer> policyT,
                                             List<Integer> policyU, Model model) {
        try {
            BilinearGroup bg = getSystemParameters().getBilinearGroup();
            Element g = bg.getGenerator();
            Element[] h = getSystemParameters().getH();
            int n = getSystemParameters().getn();

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

                ca1[i] = getPublicParameters().getC()[k].duplicate().getImmutable();

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

                ct1[i] = getPublicParameters().getC()[k].duplicate().getImmutable();

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

                cu1[i] = getPublicParameters().getC()[k].duplicate().getImmutable();

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
            List<ServerShare> serverShares = splitHomomorphicKey(ska, bg);
            for (ServerShare share : serverShares) {
                serverKeyShares.put(share.getServerId(), share.getKeyShare());
            }
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

            return new DistributedProcessedModel(
                    policyA, policyT, policyU,
                    caParams, ctParams, cuParams,
                    pka, skt, pku, ct6, model, ca6, ct6, null, serverShares
            );

        } catch (Exception e) {
            throw new RuntimeException("Full-Webman Process algorithm failed", e);
        }
    }

    public double[] avail(Element skid, Element Lid, Element[] Ra, double[] m,
                          WebmanUtils.ProcessedModel processedModel) {
        try {
            BilinearGroup bg = getSystemParameters().getBilinearGroup();
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
            List<ServerShare> availableShares = new ArrayList<>();
            for (int serverId : serverIds) {
                if (serverKeyShares.containsKey(serverId)) {
                    Element serverData = bg.randomG1();
                    ServerShare share = new ServerShare(serverId, serverKeyShares.get(serverId), serverData);
                    availableShares.add(share);
                }
            }
            int threshold = numServers / 2 + 1;
            if (availableShares.size() < threshold) {
                throw new RuntimeException("Insufficient server shares for collaborative decryption");
            }
            double[] SR = collaborativeDecrypt(ESR, availableShares, pka);
            return SR;

        } catch (Exception e) {
            throw new RuntimeException("Full-Webman Avail algorithm failed", e);
        }
    }

    @Override
    public byte[] train(Element skid, Element Lid, Element[] Rt,
                        WebmanUtils.ProcessedModel processedModel) {
        return super.train(skid, Lid, Rt, processedModel);
    }

    @Override
    public WebmanUtils.ProcessedModel upgrade(Element skid, Element Lid, Element[] Ru,
                                              List<byte[]> trainedModels,
                                              WebmanUtils.ProcessedModel processedModel) {
        try {
            BilinearGroup bg = getSystemParameters().getBilinearGroup();
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
            PaillierEncryption paillier = new PaillierEncryption(1024);
            PaillierEncryption.KeyPair newKeys = paillier.generateKeyPair();
            PaillierEncryption.PublicKey newPka = newKeys.getPublicKey();
            PaillierEncryption.PrivateKey newSka = newKeys.getPrivateKey();
            List<ServerShare> newShares = splitHomomorphicKey(newSka, bg);
            serverKeyShares.clear();
            for (ServerShare share : newShares) {
                serverKeyShares.put(share.getServerId(), share.getKeyShare());
            }
            BigInteger modelValue = new BigInteger(1, aggregatedModelBytes);
            BigInteger newCa6 = paillier.encrypt(modelValue, newPka);
            byte[] combinedData = concatenateBytes(newCa6.toByteArray(), newCt6);
            ChameleonHash chameleonHash = new ChameleonHash();
            ChameleonHash.PublicKey pku = processedModel.getChameleonPK();
            ChameleonHash.HashResult newHashResult = chameleonHash.hash(combinedData, pku);
            List<Integer> emptyPolicy = new ArrayList<>();
            Element[] emptyParams = new Element[6];
            return new DistributedProcessedModel(
                    emptyPolicy, emptyPolicy, emptyPolicy,
                    emptyParams, emptyParams, emptyParams,
                    newPka, skt, pku, newCt6, aggregatedModel, newCa6, newCt6, null, newShares
            );

        } catch (Exception e) {
            throw new RuntimeException("Full-Webman Upgrade algorithm failed", e);
        }
    }
    private List<ServerShare> splitHomomorphicKey(PaillierEncryption.PrivateKey ska,
                                                  BilinearGroup bg) {
        List<ServerShare> shares = new ArrayList<>();
        BigInteger lambda = ska.getLambda();
        BigInteger mu = ska.getMu();
        int threshold = numServers / 2 + 1;
        BigInteger[] lambdaShares = shamirSecretSharing(lambda, numServers, threshold);
        BigInteger[] muShares = shamirSecretSharing(mu, numServers, threshold);
        for (int i = 0; i < numServers; i++) {
            int serverId = i + 1;
            BigInteger keyShare = lambdaShares[i].add(muShares[i]);
            Element serverData = bg.randomG1();
            ServerShare share = new ServerShare(serverId, keyShare, serverData);
            shares.add(share);
        }

        return shares;
    }
    
    private BigInteger[] shamirSecretSharing(BigInteger secret, int n, int t) {
        return ShamirSecretSharing.split(secret, n, t);
    }

    private double[] collaborativeDecrypt(BigInteger encryptedResult,
                                          List<ServerShare> serverShares,
                                          PaillierEncryption.PublicKey pka) {
        try {
            int threshold = numServers / 2 + 1;
            if (serverShares.size() < threshold) {
                throw new RuntimeException("Insufficient server shares for threshold decryption");
            }
            BigInteger reconstructedKey = BigInteger.ZERO;
            BigInteger modulus = pka.getN();
            for (int i = 0; i < threshold && i < serverShares.size(); i++) {
                ServerShare share = serverShares.get(i);
                BigInteger shareValue = share.getKeyShare();
                BigInteger lagrangeCoeff = BigInteger.ONE;
                for (int j = 0; j < threshold && j < serverShares.size(); j++) {
                    if (i != j) {
                        ServerShare otherShare = serverShares.get(j);
                        int xi = share.getServerId();
                        int xj = otherShare.getServerId();
                        BigInteger numerator = BigInteger.valueOf(-xj);
                        BigInteger denominator = BigInteger.valueOf(xi - xj);
                        if (!denominator.equals(BigInteger.ZERO)) {
                            BigInteger denominatorInv = denominator.modInverse(modulus);
                            lagrangeCoeff = lagrangeCoeff.multiply(numerator)
                                    .multiply(denominatorInv)
                                    .mod(modulus);
                        }
                    }
                }
                BigInteger weightedContribution = shareValue.multiply(lagrangeCoeff).mod(modulus);
                reconstructedKey = reconstructedKey.add(weightedContribution).mod(modulus);
            }
            PaillierEncryption paillier = new PaillierEncryption(1024);
            PaillierEncryption.PrivateKey reconstructedSka =
                    new PaillierEncryption.PrivateKey(reconstructedKey, reconstructedKey);
            BigInteger decryptedValue = paillier.decrypt(encryptedResult, reconstructedSka);
            double prediction = HomomorphicMLPEvaluator.decodeResult(decryptedValue);
            return new double[]{prediction};
        } catch (Exception e) {
            throw new RuntimeException("Collaborative decryption failed", e);
        }
    }
    
    public static class FullWebmanSetupResult {
        public final SemiWebman.CommonReferenceString crs;
        public final Element[] pp;
        public final Element[][] aux;
        public final int numServers;
        public final List<Integer> serverIds;
        public final Map<Integer, BigInteger> serverSharesMap;
        public final int threshold;

        public FullWebmanSetupResult(SemiWebman.CommonReferenceString crs, Element[] pp,
                                     Element[][] aux, int numServers,
                                     List<Integer> serverIds, Map<Integer, BigInteger> serverSharesMap,
                                     int threshold) {
            this.crs = crs;
            this.pp = pp;
            this.aux = aux;
            this.numServers = numServers;
            this.serverIds = serverIds;
            this.serverSharesMap = serverSharesMap;
            this.threshold = threshold;
        }
    }

    public static class ServerShare {
        private int serverId;
        private BigInteger keyShare;
        private Element serverData;

        public ServerShare(int serverId, BigInteger keyShare, Element serverData) {
            this.serverId = serverId;
            this.keyShare = keyShare;
            this.serverData = serverData;
        }

        public int getServerId() {
            return serverId;
        }

        public BigInteger getKeyShare() {
            return keyShare;
        }

        public Element getServerData() {
            return serverData;
        }
    }

    public static class DistributedProcessedModel extends WebmanUtils.ProcessedModel {
        private List<ServerShare> serverShares;

        public DistributedProcessedModel(List<Integer> policyA, List<Integer> policyT, List<Integer> policyU,
                                         Element[] caParams, Element[] ctParams, Element[] cuParams,
                                         PaillierEncryption.PublicKey paillierPK, SecretKey aesKey,
                                         ChameleonHash.PublicKey chameleonPK, byte[] encryptedModel,
                                         Model model, BigInteger ca6, byte[] ct6,
                                         PaillierEncryption.PrivateKey paillierSK, List<ServerShare> serverShares) {
            super(policyA, policyT, policyU, caParams, ctParams, cuParams,
                    paillierPK, aesKey, chameleonPK, encryptedModel, model, ca6, ct6, paillierSK);
            this.serverShares = serverShares;
        }

        public List<ServerShare> getServerShares() {
            return serverShares;
        }
    }
}