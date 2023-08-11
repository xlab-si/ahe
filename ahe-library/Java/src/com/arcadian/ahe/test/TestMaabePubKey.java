package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.MaabePubKey;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabePubKey extends TestCase {
    public void testIsEmpty() {
        MaabePubKey m1 = new MaabePubKey();
        assertTrue(m1.isEmpty());
        String[] bad = new String[]{"1", "2"};
        MaabePubKey m2 = new MaabePubKey(bad);
        assertTrue(m2.isEmpty());
        String[] good = new String[]{"1", "2", "3"};
        MaabePubKey m3 = new MaabePubKey(good);
        assertFalse(m3.isEmpty());
    }

    public void testToStringList() {
        MaabePubKey m1 = new MaabePubKey();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> m1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
