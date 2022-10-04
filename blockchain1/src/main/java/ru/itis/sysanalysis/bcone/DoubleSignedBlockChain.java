package ru.itis.sysanalysis.bcone;

import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

import static ru.itis.sysanalysis.bcone.Utils.DIGEST_ALGORITHM;

public class DoubleSignedBlockChain {

    private static final int BC_LENGTH = 20;

    private static KeyPair keyPair;

    private static final String STORAGE = "blockchain.txt";
    private static final String PREV_HASH = "prev_hash.txt";

    public static void main(String[] args) {
        try {
            // загрузка ранее сгенерированных ключей владельца блокчейна
            keyPair = Utils.loadKeys();
            // создание блокчейна
            makeBlockChain();

            print();

            // верификация
            System.out.println("verification result: " + verification());

            damage();

            print();

            System.out.println("verification result: " + verification());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void makeBlockChain() {
        byte[] prevHash = loadLastHash();

        byte[] dataHash;

        try (ObjectOutputStream oos = openFileToWrite()) {

            for (int i = 0; i < BC_LENGTH; i++) {
                BlockInfo blockInfo = new BlockInfo(new Date());
                blockInfo.getData().add("{\"data\":\"data " + UUID.randomUUID() + "\"}");
                blockInfo.getData().add("{\"timestamp\":\"" + new Date() + "\"}");
                blockInfo.setPrevHash(prevHash);

                try {
                    // hash by data only
                    dataHash = getHash(blockInfo.getData());
                    blockInfo.setSignData(Utils.generateRSAPSSSignature(generateKeys(dataHash), dataHash));

                    // hash based on prev hash and current hash
                    prevHash = Utils.getHash(blockInfo);

                    // подпись блока при помощи приватного ключа
                    blockInfo.setSign(Utils.generateRSAPSSSignature(keyPair.getPrivate(), prevHash));
                } catch (Exception e) {
                    e.printStackTrace();
                }

                saveBlock(blockInfo, oos);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            updateLastHash(prevHash);
        }
    }

    private static void print() throws NoSuchAlgorithmException, NoSuchProviderException {
        BlockInfo bi;
        try (ObjectInputStream ois = openFileToRead()) {
            while ((bi = loadNextBlock(ois)) != null) {

                System.out.println("===================== " + bi.getCreatedAt().toString() + " =============================");
                System.out.println("prev hash: " + (bi.getPrevHash() != null ? new String(Hex.encode(bi.getPrevHash())) : ""));
                for (String s : bi.getData()) System.out.println(s);
                System.out.println("hash: " + new String(Hex.encode(Utils.getHash(bi))));
                System.out.println("signature: " + new String(Hex.encode(bi.getSign())));
                System.out.println("data signature: " + new String(Hex.encode(bi.getSignData())));
                System.out.println();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verification() throws GeneralSecurityException {
        // auto-close after verification

        try (ObjectInputStream ois = openFileToRead()) {

            BlockInfo block = loadNextBlock(ois);
            byte[] prevHash = Utils.getHash(Objects.requireNonNull(block));

            while ((block = loadNextBlock(ois)) != null) {
                if (!Arrays.equals(prevHash, block.getPrevHash())) {
                    return false;
                }

                prevHash = Utils.getHash(block);
                byte[] dataHash = getHash(block.getData());

                // верификация цифровой подписи над блоком
                if (!Utils.verifyRSAPSSSignature(keyPair.getPublic(), prevHash, block.getSign())) {
                    return false;
                }

                // верификация цифровой подписи над данными
                if (!Utils.verifyRSAPSSSignature(loadPublicKey(dataHash), dataHash, block.getSignData())) {
                    return false;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return true;
    }

    private static void damage() {
        try (ObjectInputStream ois = openFileToRead()) {

            List<BlockInfo> blockchain = new ArrayList<>();
            BlockInfo blockInfo;

            while ((blockInfo = loadNextBlock(ois)) != null) {
                blockchain.add(blockInfo);
            }

            Random random = new Random();

            BlockInfo damaged = blockchain.get(random.nextInt(blockchain.size() - 2));
            damaged.setData(List.of("{ Damaged Data }"));

            try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(STORAGE))) {
                blockchain.forEach(block -> saveBlock(block, oos));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // open file to write
    private static ObjectInputStream openFileToRead() {
        try {
            FileInputStream fis = new FileInputStream(STORAGE);

            return new ObjectInputStream(fis);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // open file to write
    private static ObjectOutputStream openFileToWrite() {
        try {
            File f = new File(STORAGE);
            if(f.exists()) {
                FileOutputStream fos = new FileOutputStream(STORAGE, true);

                return new ObjectOutputStream(fos) {
                    protected void writeStreamHeader() throws IOException {
                        reset();
                    }
                };
            } else {
                FileOutputStream fos = new FileOutputStream(STORAGE);
                return new ObjectOutputStream(fos);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // save blockinfo to storage
    private static void saveBlock(BlockInfo blockInfo, ObjectOutputStream oos) {
        try {
            oos.writeObject(blockInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // load blockinfo from storage
    private static BlockInfo loadNextBlock(ObjectInputStream ois) {
        try {
            return (BlockInfo) ois.readObject();
        } catch (EOFException e) {
            return null;
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }


    // generate public and private key for each blockinfo
    private static PrivateKey generateKeys(byte[] hash) {
        // блок кода который генерирует нам пару public/private ключей

        String filename = new String(Hex.encode(hash));

        KeyPairGenerator rsa;
        try (Writer publicKeyWriter = new FileWriter("keys/" + filename + "_public.key")) {

            rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(1024, new SecureRandom());
            KeyPair keyPair = rsa.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            publicKeyWriter.write(new String(Hex.encode(publicKey.getEncoded())));

            return keyPair.getPrivate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    // load particular public key for block info verification
    private static PublicKey loadPublicKey(byte[] hash) {
        String filename = new String(Hex.encode(hash));

        try {
            byte[] publicKeyHex = Files.readAllBytes(Paths.get("keys/" +filename + "_public.key"));

            return Utils.convertArrayToPublicKey(Hex.decode(publicKeyHex), "RSA");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // update last hash
    private static void updateLastHash(byte[] hash) {
        try (FileOutputStream fos = new FileOutputStream(PREV_HASH)) {
            fos.write(hash);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // load last hash
    private static byte[] loadLastHash() {
        try (FileInputStream fis = new FileInputStream(PREV_HASH)) {
            return fis.readAllBytes();
        } catch (FileNotFoundException e) {
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // подсчет хеша для блока с данными не путать с блоком блокчейна
    private static byte[] getHash(List<String> data) throws NoSuchAlgorithmException, NoSuchProviderException {
        StringBuilder info = new StringBuilder();

        for (String s : data) {
            info.append(s);
        }

        MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM, "BC");

        return digest.digest(info.toString().getBytes(StandardCharsets.UTF_8));
    }

}
