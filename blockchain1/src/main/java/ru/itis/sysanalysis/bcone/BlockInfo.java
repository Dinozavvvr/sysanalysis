package ru.itis.sysanalysis.bcone;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * структура элемента блокчейна
 * - id
 * - data: массив данных
 * - prevHash - хешкод предыдущего блока
 * - sign - подпись блока
 * - signData - подпись данных
 */
public class BlockInfo implements Serializable {

    private Date createdAt;

    private List<String> data = new ArrayList<>();

    private byte[] prevHash;

    private byte[] sign;

    private byte[] signData;

    public BlockInfo(Date blockNum) {
        this.createdAt = blockNum;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date blockNum) {
        this.createdAt = blockNum;
    }

    public List<String> getData() {
        return data;
    }

    public void setData(List<String> data) {
        this.data = data;
    }

    public byte[] getPrevHash() {
        return prevHash;
    }

    public void setPrevHash(byte[] prevHash) {
        this.prevHash = prevHash;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public byte[] getSignData() {
        return signData;
    }

    public void setSignData(byte[] signData) {
        this.signData = signData;
    }
}
