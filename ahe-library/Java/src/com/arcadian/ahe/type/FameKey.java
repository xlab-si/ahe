package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents an attribute decryption key in the Fame scheme.
 *
 */
public class FameKey {
    /**
     * Internal value of Fame key.
     */
    public String K0 = "";
    /**
     * Internal value of Fame key.
     */
    public String KPrime = "";
    /**
     * The string attribute this key represents.
     */
    public String Attribs = "";
    /**
     * A string marshalled and base64 encoded key.
     */
    public String[] K = new String[]{};

    /**
     * Default constructor creates an empty object.
     */
    public FameKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   keyStr  the string array of serialized parameters
     */
    public FameKey(String[] keyStr) {
        if (keyStr.length >= 3) {
            K0 = keyStr[0];
            KPrime = keyStr[1];
            Attribs = keyStr[2];
            String[] k = new String[keyStr.length - 3];
            for (int i = 3; i < keyStr.length; i++) {
                k[i - 3] = keyStr[i];
            }
            K = k;
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
        String[] ret = new String[3 + K.length];
        ret[0] = K0;
        ret[1] = KPrime;
        ret[2] = Attribs;

       for (int i = 0; i < K.length; i++) {
            ret[3 + i] = K[i];
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
        return K0.equals("") || Attribs.equals("") || KPrime.equals("") || K.length == 0;
    }
}
