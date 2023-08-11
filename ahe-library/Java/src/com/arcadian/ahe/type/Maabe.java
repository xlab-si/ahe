package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents the global information of the Maabe scheme.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class Maabe {
    /**
     * A string prime order of the underlying curve.
     */
    public String P = "";
    /**
     * A string marshalled and base64 encoded generator of the first group.
     */
    public String G1 = "";
    /**
     * A string marshalled and base64 encoded generator of the second group.
     */
    public String G2 = "";
    /**
     * A string marshalled and base64 encoded pairing of G1 and G2.
     */
    public String Gt = "";

    /**
     * Default constructor creates an empty object.
     */
    public Maabe() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   maabeStrList    the string array of serialized parameters
     */
    public Maabe(String[] maabeStrList) {
        if (maabeStrList.length == 4) {
            P = maabeStrList[0];
            G1 = maabeStrList[1];
            G2 = maabeStrList[2];
            Gt = maabeStrList[3];
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
        String[] ret = new String[4];
        ret[0] = P;
        ret[1] = G1;
        ret[2] = G2;
        ret[3] = Gt;
        return ret;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return P.equals("") || G1.equals("") || G2.equals("") || Gt.equals("");
    }
}
