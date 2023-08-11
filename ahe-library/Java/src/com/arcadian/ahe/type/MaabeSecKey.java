package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a collection of secret keys in the Maabe scheme
 * belonging to a single authority.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class MaabeSecKey {
    /**
     * A string list of attributes managed by this authority.
     */
    public String[] attrib = new String[]{};
    /**
     * A list of string marshalled and base64 encoded secret keys (1/2), one for each attribute.
     */
    public String[] alpha = new String[]{};
    /**
     * A list of string marshalled and base64 encoded secret keys (2/2), one for each attribute.
     */
    public String[] y = new String[]{};

    /**
     * Default constructor creates an empty object.
     */
    public MaabeSecKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   seckeyStr   the string array of serialized parameters
     */
    public MaabeSecKey(String[] seckeyStr) {
        if (seckeyStr.length % 3 == 0) {
            String[] at = new String[seckeyStr.length / 3];
            String[] ta = new String[seckeyStr.length / 3];
            String[] ty = new String[seckeyStr.length / 3];
            for (int i = 0; i < seckeyStr.length / 3; i++) {
                at[i] = seckeyStr[3 * i + 0];
                ta[i] = seckeyStr[3 * i + 1];
                ty[i] = seckeyStr[3 * i + 2];
            }
            attrib = at;
            alpha = ta;
            y = ty;
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
        String[] ret = new String[3 * attrib.length];
        for (int i = 0; i < attrib.length; i++) {
            ret[3 * i + 0] = attrib[i];
            ret[3 * i + 1] = alpha[i];
            ret[3 * i + 2] = y[i];
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
        return attrib.length == 0 || alpha.length == 0 || y.length == 0;
    }
}

