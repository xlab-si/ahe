package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a ciphertext in the Fame scheme.
 *
 */
public class FameCipher {
    /**
     * A base64 encoded ciphertext of the AES-128 encrypted message.
     */
    public String SymEnc = "";
    /**
     * A base64 encoded Iv for AES-128.
     */
    public String Iv = "";
    /**
     * Component of the MSP: prime P.
     * Not used anywhere, so permanently set to the string "0".
     */
    public String MSP_P = "";
    /**
     * Component of the MSP: matrix.
     * A string serialization of the MSP matrix as used by <code>libahe.so</code>.
     */
    public String MSP_Mat = "";
    /**
     * Component of the MSP: matrix row to attribute map.
     * A space-concatenated list of attributes, in order as they are
     * represented by the above matrix's rows.
     */
    public String MSP_RowToAttrib = "";
    /**
     * Internal value of Fame cipher.
     */
    public String C0 = "";
    /**
     * Internal value of Fame cipher.
     */
    public String CPrime = "";
    /**
     * Internal value of Fame cipher.
     */
    public String[] Ct = new String[]{};

    /**
     * Default constructor creates an empty object.
     */
    public FameCipher() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   cipherStrList   the string array of serialized parameters
     */
    public FameCipher(String[] cipherStrList) {
        if (cipherStrList.length >= 7) {
            SymEnc = cipherStrList[0];
            Iv = cipherStrList[1];
            MSP_P = cipherStrList[2];
            MSP_Mat = cipherStrList[3];
            MSP_RowToAttrib = cipherStrList[4];
            C0 = cipherStrList[5];
            CPrime = cipherStrList[6];
            String[] ct = new String[cipherStrList.length - 7];
            for (int i = 7; i < cipherStrList.length; i++) {
                ct[i - 7] = cipherStrList[i];
            }
            Ct = ct;
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
        String[] ret = new String[7 + Ct.length];
        ret[0] = SymEnc;
        ret[1] = Iv;
        ret[2] = MSP_P;
        ret[3] = MSP_Mat;
        ret[4] = MSP_RowToAttrib;
        ret[5] = C0;
        ret[6] = CPrime;
        for (int i = 0; i < Ct.length; i++) {
            ret[7 + i] = Ct[i];
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
        return (SymEnc.equals("")
                || Iv.equals("")
                || MSP_P.equals("")
                || MSP_Mat.equals("")
                || MSP_RowToAttrib.equals("")
                || Ct.length == 0);
    }
}

