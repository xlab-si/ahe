package com.arcadian.ahe.test;

import junit.framework.TestCase;
import static org.junit.Assert.assertThrows;

import com.arcadian.ahe.type.Maabe;
import com.arcadian.ahe.exception.AheOperationOnEmptyObject;

public class TestMaabe extends TestCase {
    public void testIsEmpty() {
        Maabe m1 = new Maabe();
        assertTrue(m1.isEmpty());
        String[] bad = new String[]{"1", "2", "3"};
        Maabe m2 = new Maabe(bad);
        assertTrue(m2.isEmpty());
        String[] good = new String[]{"1", "2", "3", "4"};
        Maabe m3 = new Maabe(good);
        assertFalse(m3.isEmpty());
    }

    public void testToStringList() {
        Maabe m1 = new Maabe();
        AheOperationOnEmptyObject err = assertThrows(AheOperationOnEmptyObject.class, () -> m1.toStringList());
        assertEquals(err.getMessage(), "");
    }
}
