package com.arcadian.ahe.type;
import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import java.util.List;
import java.util.Arrays;
import com.arcadian.ahe.type.FameSecKey;
import com.arcadian.ahe.type.FamePubKey;

import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

/**
 * This class represents a secret and public key in Fame scheme.
 *
 */
public class FameMasterKey {
    public FamePubKey pubKey;
    public FameSecKey secKey;

    public FameMasterKey(FamePubKey pubkey, FameSecKey seckey) {
        pubKey = pubkey;
        secKey = seckey;
    }
}