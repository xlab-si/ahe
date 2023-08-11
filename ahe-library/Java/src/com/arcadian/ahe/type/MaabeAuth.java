package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;
import java.util.Arrays;

/**
 * This class represents an authority in the Maabe scheme.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class MaabeAuth {
    /**
     * The string identifier of this authority.
     */
    public String ID = "";
    /**
     * The collection of global properties.
     */
    public Maabe maabe = new Maabe();
    /**
     * The public keys of this authority.
     */
    public MaabePubKey Pk = new MaabePubKey();
    /**
     * The secret keys of this authority.
     */
    public MaabeSecKey Sk = new MaabeSecKey();

    /**
     * Default constructor creates an empty object.
     */
    public MaabeAuth() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   authStrList the string array of serialized parameters
     */
    public MaabeAuth(String[] authStrList) {
        if (authStrList.length % 5 == 0 && authStrList.length >= 5) {
            ID = authStrList[0];
            maabe = new Maabe(Arrays.copyOfRange(authStrList, 1, 5));
            String[] atp = new String[(authStrList.length - 5) / 5];
            String[] ats = new String[(authStrList.length - 5) / 5];
            String[] eg = new String[(authStrList.length - 5) / 5];
            String[] gt = new String[(authStrList.length - 5) / 5];
            String[] ta = new String[(authStrList.length - 5) / 5];
            String[] ty = new String[(authStrList.length - 5) / 5];
            for (int i = 0; i < (authStrList.length - 5) / 5; i++) {
                atp[i] = authStrList[5 * i + 5];
                ats[i] = authStrList[5 * i + 5];
                eg[i] = authStrList[5 * i + 6];
                gt[i] = authStrList[5 * i + 7];
                ta[i] = authStrList[5 * i + 8];
                ty[i] = authStrList[5 * i + 9];
            }
            Pk.attrib = atp;
            Pk.eggToAlpha = eg;
            Pk.gToY = gt;
            Sk.attrib = ats;
            Sk.alpha = ta;
            Sk.y = ty;
        }
    }

    /**
     * Transfers the object's properties back into a string array.
     *
     * @return  a string list representing this object
     * @throws  AheOperationOnEmptyObject   if the object is considered empty
     */
    public String[] toStringList()
    throws AheOperationOnEmptyObject {
        if (this.isEmpty()) {
            throw new AheOperationOnEmptyObject("");
        }
        String[] ret = new String[5 + 5 * Pk.attrib.length];
        String[] maabeStr = maabe.toStringList();
        String[] pkList = Pk.toStringList();
        String[] skList = Sk.toStringList();
        ret[0] = ID;
        for (int i = 0; i < 4; i++) {
            ret[i + 1] = maabeStr[i];
        }
        for (int i = 0; i < pkList.length / 3; i++) {
            ret[5 * i + 5] = pkList[3 * i + 0];
            ret[5 * i + 6] = pkList[3 * i + 1];
            ret[5 * i + 7] = pkList[3 * i + 2];
            ret[5 * i + 8] = skList[3 * i + 1];
            ret[5 * i + 9] = skList[3 * i + 2];
        }
        return ret;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return ID.equals("") || maabe.isEmpty() || Pk.isEmpty() || Sk.isEmpty();
    }
}

