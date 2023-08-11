package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a collection of public keys in the Maabe scheme
 * belonging to a single authority.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class MaabePubKey {
    /**
     * A string list of attributes managed by this authority.
     */
    public String[] attrib = new String[]{};
    /**
     * A list of string marshalled and base64 encoded public keys (1/2), one for each attribute.
     */
    public String[] eggToAlpha = new String[]{};
    /**
     * A list of string marshalled and base64 encoded public keys (2/2), one for each attribute.
     */
    public String[] gToY = new String[]{};

    /**
     * Default constructor creates an empty object.
     */
    public MaabePubKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   pubkeyStr   the string array of serialized parameters
     */
    public MaabePubKey(String[] pubkeyStr) {
        if (pubkeyStr.length % 3 == 0) {
            String[] at = new String[pubkeyStr.length / 3];
            String[] eg = new String[pubkeyStr.length / 3];
            String[] gt = new String[pubkeyStr.length / 3];
            for (int i = 0; i < pubkeyStr.length / 3; i++) {
                at[i] = pubkeyStr[3 * i + 0];
                eg[i] = pubkeyStr[3 * i + 1];
                gt[i] = pubkeyStr[3 * i + 2];
            }
            attrib = at;
            eggToAlpha = eg;
            gToY = gt;
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
            ret[3 * i + 1] = eggToAlpha[i];
            ret[3 * i + 2] = gToY[i];
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
        return attrib.length == 0 || eggToAlpha.length == 0 || gToY.length == 0;
    }
}
