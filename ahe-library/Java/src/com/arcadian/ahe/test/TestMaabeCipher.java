package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.MaabeCipher;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabeCipher extends TestCase {
    public void testIsEmpty() {
        MaabeCipher m1 = new MaabeCipher();
        assertTrue(m1.isEmpty());
        String[] bad = new String[]{"1", "2", "3"};
        MaabeCipher m2 = new MaabeCipher(bad);
        assertTrue(m2.isEmpty());
        String[] good = new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
        MaabeCipher m3 = new MaabeCipher(good);
        assertFalse(m3.isEmpty());
    }

    public void testToStringList() {
        MaabeCipher m1 = new MaabeCipher();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> m1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
