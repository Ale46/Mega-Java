/*******************************************************************************
 * Copyright (c) 2013 Ale46.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Public License v3.0
 * which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/gpl.html
 * 
 * Contributors:
 *     @NT2005 - initial API and implementation
 ******************************************************************************/
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class MegaCrypt {
	private static final char[] CA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
	private static final int[] IA = new int[256];
	static {
		Arrays.fill(IA, -1);
		for (int i = 0, iS = CA.length; i < iS; i++)
			IA[CA[i]] = i;
		IA['='] = 0;
	}
	
    public static long[] prepare_key_pw(String password) {
        return prepare_key(str_to_a32(password));
    }

    public static long[] prepare_key(long[] password) {
        long[] pkey = {0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56};
        for (int r = 0; r < 0x10000; r++) {
            for (int j = 0; j < password.length; j += 4) {
                long[] key = {0, 0, 0, 0};
                for (int i = 0; i < 4; i++) {
                    if (i + j < password.length) {
                        key[i] = password[i + j];
                    }
                }
                pkey = aes_cbc_encrypt_a32(pkey, key);
            }
        }
        return pkey;
    }

    public static String stringhash(String email, long[] aeskey) {
        long[] s32 = str_to_a32(email);
        long[] h32 = {0, 0, 0, 0};
        for (int i = 0; i < s32.length; i++) {
            h32[i % 4] ^= s32[i];
        }
        for (int r = 0; r < 0x4000; r++) {
            h32 = aes_cbc_encrypt_a32(h32, aeskey);
        }
        long[] h32Part = new long[2];
        h32Part[0] = h32[0];
        h32Part[1] = h32[2];
        return a32_to_base64(h32Part);
    }

    public static byte[] aes_cbc_encrypt(byte[] data, byte[] key) {
        String iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        byte[] output = null;
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            output = cipher.doFinal(data);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return output;
    }

    public static long[] aes_cbc_encrypt_a32(long[] idata, long[] ikey) {
        try {
            byte[] data = a32_to_str(idata).getBytes("ISO-8859-1");
            byte[] key = a32_to_str(ikey).getBytes("ISO-8859-1");
            byte[] encrypt = aes_cbc_encrypt(data, key);

            return str_to_a32(new String(encrypt, "ISO-8859-1"));

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new long[0];
    }


    public static byte[] aes_cbc_decrypt(byte[] data, byte[] key) {
        String iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        byte[] output = null;
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            output = cipher.doFinal(data);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return output;
    }

    public static long[] aes_cbc_decrypt_a32(long[] idata, long[] ikey) {
        try {
            byte[] data = a32_to_str(idata).getBytes("ISO-8859-1");
            byte[] key = a32_to_str(ikey).getBytes("ISO-8859-1");
            byte[] decrypt = aes_cbc_decrypt(data, key);

            return str_to_a32(new String(decrypt, "ISO-8859-1"));

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new long[0];
    }

    public static long[] decrypt_key(long[] a, long[] key) {

        long[] sum = new long[a.length];
        for (int i = 0; i < a.length; i += 4) {
            long[] part = aes_cbc_decrypt_a32(Arrays.copyOfRange(a, i, i + 4), key);
            for (int j = i; j < i + 4; j++) {
                sum[j] = part[j - i];
            }
        }

        return sum;
    }

    public static long[] str_to_a32(String string) {
        if (string.length() % 4 != 0) {
            string += new String(new char[4 - string.length() % 4]);
        }
        long[] data = new long[string.length() / 4];

        byte[] part = new byte[8];
        for (int k = 0, i = 0; i < string.length(); i += 4, k++) {
            String sequence = string.substring(i, i + 4);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(sequence.getBytes("ISO-8859-1"));
                System.arraycopy(baos.toByteArray(), 0, part, 4, 4);
                ByteBuffer bb = ByteBuffer.wrap(part);
                data[k] = bb.getLong();
            } catch (IOException e) {
                data[k] = 0;
            }
        }
        return data;
    }

    public static String a32_to_str(long[] data) {
        byte[] part = null;
        StringBuilder builder = new StringBuilder();
        ByteBuffer bb = ByteBuffer.allocate(8);
        for (int i = 0; i < data.length; i++) {
            bb.putLong(data[i]);
            part = Arrays.copyOfRange(bb.array(), 4, 8);
            bb.clear();
            ByteArrayInputStream bais = new ByteArrayInputStream(part);
            while (bais.available() > 0) {
                builder.append((char) bais.read());
            }
        }
        return builder.toString();
    }

    public static String base64_url_encode(String data) {

        try {
            data = new String(base64_url_encode_byte((data.getBytes("ISO-8859-1")),true), "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        data = data.replaceAll("\\+", "-");
        data = data.replaceAll("/", "_");
        data = data.replaceAll("=", "");

        return data;
    }

/*    public static String base64_url_decode(String data) {
        data = data.replaceAll("-", "\\+");
        data = data.replaceAll("_", "/");
        data = data.replaceAll(",", "");
        //for (int i = 0;i<4-(data.length()%4);++i)
        data += "==";

        try {
            return new String(Base64.decodeBase64(data.getBytes("ISO-8859-1")), "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }*/

    public static String a32_to_base64(long[] a) {
        return base64_url_encode(a32_to_str(a));
    }

    public static long[] base64_to_a32(String s) throws UnsupportedEncodingException {
        return str_to_a32(base64_url_decode(s));
    }

    public static BigInteger mpi_to_int(String private_key) throws IOException {
       
            String hex = encodeHexString(private_key.substring(2));
            return new BigInteger(hex, 16);
        
    }

    public static String decrypt_attr(String attributes, long[] key) {
        try {
            return new String(aes_cbc_decrypt(attributes.getBytes("ISO-8859-1"), a32_to_str(key).getBytes("ISO-8859-1")), "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }
    
    public static byte[] aInt_to_aByte(int... intKey) {
        byte[] buffer = new byte[intKey.length * 4];
        ByteBuffer bb = ByteBuffer.wrap(buffer);
        for (int i = 0; i < intKey.length; i++) {
            bb.putInt(intKey[i]);
        }
        return bb.array();
    }

    public static int[] aByte_to_aInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        int[] res = new int[bytes.length / 4];
        for (int i = 0; i < res.length; i++) {
            res[i] = bb.getInt(i * 4);
        }
        return res;
    }
    

    public final static String base64_url_decode(String str) throws UnsupportedEncodingException{
    	return new String((base64_url_decode_byte(str)), "ISO-8859-1");
    }
    public final static byte[] base64_url_decode_byte(String str){
    	str += "==".substring((2 - str.length() * 3) & 3);
    	str = str.replace("-", "+").replace("_", "/").replace(",", "");
		// Check special case
		int sLen = str != null ? str.length() : 0;
		if (sLen == 0)
			return new byte[0];

		// Count illegal characters (including '\r', '\n') to know what size the returned array will be,
		// so we don't have to reallocate & copy it later.
		int sepCnt = 0; // Number of separator characters. (Actually illegal characters, but that's a bonus...)
		for (int i = 0; i < sLen; i++)  // If input is "pure" (I.e. no line separators or illegal chars) base64 this loop can be commented out.
			if (IA[str.charAt(i)] < 0)
				sepCnt++;

		// Check so that legal chars (including '=') are evenly divideable by 4 as specified in RFC 2045.
		if ((sLen - sepCnt) % 4 != 0)
			return null;

		// Count '=' at end
		int pad = 0;
		for (int i = sLen; i > 1 && IA[str.charAt(--i)] <= 0;)
			if (str.charAt(i) == '=')
				pad++;

		int len = ((sLen - sepCnt) * 6 >> 3) - pad;

		byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

		for (int s = 0, d = 0; d < len;) {
			// Assemble three bytes into an int from four "valid" characters.
			int i = 0;
			for (int j = 0; j < 4; j++) {   // j only increased if a valid char was found.
				int c = IA[str.charAt(s++)];
				if (c >= 0)
				    i |= c << (18 - j * 6);
				else
					j--;
			}
			// Add the bytes
			dArr[d++] = (byte) (i >> 16);
			if (d < len) {
				dArr[d++]= (byte) (i >> 8);
				if (d < len)
					dArr[d++] = (byte) i;
			}
		}
		return dArr;
	}
    
    public final static byte[] base64_url_encode_byte(byte[] sArr, boolean lineSep)
	{
		// Check special case
		int sLen = sArr != null ? sArr.length : 0;
		if (sLen == 0)
			return new byte[0];

		int eLen = (sLen / 3) * 3;                              // Length of even 24-bits.
		int cCnt = ((sLen - 1) / 3 + 1) << 2;                   // Returned character count
		int dLen = cCnt + (lineSep ? (cCnt - 1) / 76 << 1 : 0); // Length of returned array
		byte[] dArr = new byte[dLen];

		// Encode even 24-bits
		for (int s = 0, d = 0, cc = 0; s < eLen;) {
			// Copy next three bytes into lower 24 bits of int, paying attension to sign.
			int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

			// Encode the int into four chars
			dArr[d++] = (byte) CA[(i >>> 18) & 0x3f];
			dArr[d++] = (byte) CA[(i >>> 12) & 0x3f];
			dArr[d++] = (byte) CA[(i >>> 6) & 0x3f];
			dArr[d++] = (byte) CA[i & 0x3f];

			// Add optional line separator
			if (lineSep && ++cc == 19 && d < dLen - 2) {
				dArr[d++] = '\r';
				dArr[d++] = '\n';
				cc = 0;
			}
		}

		// Pad and encode last bits if source isn't an even 24 bits.
		int left = sLen - eLen; // 0 - 2.
		if (left > 0) {
			// Prepare the int
			int i = ((sArr[eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

			// Set last four chars
			dArr[dLen - 4] = (byte) CA[i >> 12];
			dArr[dLen - 3] = (byte) CA[(i >>> 6) & 0x3f];
			dArr[dLen - 2] = left == 2 ? (byte) CA[i & 0x3f] : (byte) '=';
			dArr[dLen - 1] = '=';
		}
		return dArr;
	}
    
    public static String encodeHexString(String s) throws IOException {
        return DatatypeConverter.printHexBinary(s.getBytes("ISO-8859-1"));
    }
    
    public static byte[] decodeHexString(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }
    
    public static void print(Object o) {
        System.out.println(o);
    }
}


