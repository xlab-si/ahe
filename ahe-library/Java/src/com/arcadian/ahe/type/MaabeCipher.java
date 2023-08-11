package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a ciphertext in the Maabe scheme.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class MaabeCipher {
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
     * A string Maabe-encrypted, marhalled and base64 encoded key for AES-128 (1/4).
     */
    public String C0 = "";
    /**
     * A list of attributes used during encryption.
     */
    public String[] attrib = new String[]{};
    /**
     * A string Maabe-encrypted, marhalled and base64 encoded key for AES-128
     * (2/4), one for each attribute.
     */
    public String[] C1 = new String[]{};
    /**
     * A string Maabe-encrypted, marhalled and base64 encoded key for AES-128
     * (3/4), one for each attribute.
     */
    public String[] C2 = new String[]{};
    /**
     * A string Maabe-encrypted, marhalled and base64 encoded key for AES-128
     * (4/4), one for each attribute.
     */
    public String[] C3 = new String[]{};

    /**
     * Default constructor creates an empty object.
     */
    public MaabeCipher() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   cipherStrList   the string array of serialized parameters
     */
    public MaabeCipher(String[] cipherStrList) {
        if (cipherStrList.length >= 6 && (cipherStrList.length - 6) % 4 == 0) {
            SymEnc = cipherStrList[0];
            Iv = cipherStrList[1];
            MSP_P = cipherStrList[2];
            MSP_Mat = cipherStrList[3];
            MSP_RowToAttrib = cipherStrList[4];
            C0 = cipherStrList[5];
            String[] at = new String[(cipherStrList.length - 6) / 4];
            String[] c1 = new String[(cipherStrList.length - 6) / 4];
            String[] c2 = new String[(cipherStrList.length - 6) / 4];
            String[] c3 = new String[(cipherStrList.length - 6) / 4];
            for (int i = 0; i < (cipherStrList.length - 6) / 4; i++) {
                at[i] = cipherStrList[4 * i + 6];
                c1[i] = cipherStrList[4 * i + 7];
                c2[i] = cipherStrList[4 * i + 8];
                c3[i] = cipherStrList[4 * i + 9];
            }
            attrib = at;
            C1 = c1;
            C2 = c2;
            C3 = c3;
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
        String[] ret = new String[6 + 4 * attrib.length];
        ret[0] = SymEnc;
        ret[1] = Iv;
        ret[2] = MSP_P;
        ret[3] = MSP_Mat;
        ret[4] = MSP_RowToAttrib;
        ret[5] = C0;
        for (int i = 0; i < attrib.length; i++) {
            ret[4 * i + 6] = attrib[i];
            ret[4 * i + 7] = C1[i];
            ret[4 * i + 8] = C2[i];
            ret[4 * i + 9] = C3[i];
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
                || attrib.length == 0
                || C1.length == 0
                || C2.length == 0
                || C3.length == 0);
    }
}

