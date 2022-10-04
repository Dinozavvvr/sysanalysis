package ru.itis.sysanalysis.bcone;

import org.bouncycastle.util.encoders.Hex;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class SimpleBlockChain {

    private static final int BC_LENGTH = 10;

    // Простой блокчейн в листовом представлении
    private static List<BlockInfo> blockchain = new ArrayList<>();

    public static void main(String[] args) {
        // создание !
        makeBlockChain();

        try {
            print();

            // верификация !
            System.out.println("verification result: " + verification());

            damage();

            print();

            System.out.println("verification result: " + verification());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void makeBlockChain() {
        byte[] prevHash = null;

        for (int i = 0;i < BC_LENGTH; i++) {
            BlockInfo blockInfo = new BlockInfo(new Date());
            blockInfo.getData().add("{\"data\":\"data " + i + "\"}");
            blockInfo.getData().add("{\"timestamp\":\"" + new Date() + "\"}");
            blockInfo.setPrevHash(prevHash);

            try {
                prevHash = Utils.getHash(blockInfo);
                System.out.println(new String(Hex.encode(prevHash)));
            } catch (Exception e) {
                e.printStackTrace();
            }

            blockchain.add(blockInfo);
        }
    }

    private static void print() throws NoSuchAlgorithmException, NoSuchProviderException {
        for (int i = 0;i < BC_LENGTH; i++) {
            BlockInfo bi = blockchain.get(i);
            System.out.println("===================== " + bi.getCreatedAt().toString() + " =============================");
            System.out.println("prev hash: " + (bi.getPrevHash() != null ? new String(Hex.encode(bi.getPrevHash())): ""));
            for (String s: bi.getData()) System.out.println(s);
            System.out.println("hash: " + new String(Hex.encode(Utils.getHash(bi))));
            System.out.println();
        }
    }

    private static boolean verification() throws NoSuchAlgorithmException,
            NoSuchProviderException {

        byte[] prevHash = Utils.getHash(blockchain.get(0));

        for (int i = 1;i < BC_LENGTH; i++) {
            if (!Arrays.equals(prevHash, blockchain.get(i).getPrevHash())) {
                return false;
            }

            prevHash = Utils.getHash(blockchain.get(i));
        }

        return true;
    }

    private static void damage() {
        blockchain.get(3).getData().remove(0);
        blockchain.get(3).getData().add(0,"{\"data\":\"damaged data\"}");
    }
}
