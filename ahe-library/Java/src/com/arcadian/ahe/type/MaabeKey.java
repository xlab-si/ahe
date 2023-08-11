package com.arcadian.ahe.type;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents an attribute decryption key in the Maabe scheme.
 *
 * @author Benjamin Benčina
 * @version 0.0.1
 */
public class MaabeKey {
    /**
     * The string global identifier of the key's owner.
     */
    public String gid = "";
    /**
     * The string attribute this key represents.
     */
    public String attrib = "";
    /**
     * A string marshalled and base64 encoded key.
     */
    public String key = "";

    /**
     * Default constructor creates an empty object.
     */
    public MaabeKey() {
    }

    /**
     * This constructor takes in serialized parameters and sets them in the object.
     *
     * @param   keyStr  the string array of serialized parameters
     */
    public MaabeKey(String[] keyStr) {
        if (keyStr.length == 3) {
            gid = keyStr[0];
            attrib = keyStr[1];
            key = keyStr[2];
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
        String[] ret = new String[3];
        ret[0] = gid;
        ret[1] = attrib;
        ret[2] = key;
        return ret;
    }

    /**
     * Determines whether the object is considered 'empty'.
     *
     * @return  <code>true</code> if any of the object properties are empty;
     *          <code>false</code> otherwise
     */
    public boolean isEmpty() {
        return gid.equals("") || attrib.equals("") || key.equals("");
    }
}
