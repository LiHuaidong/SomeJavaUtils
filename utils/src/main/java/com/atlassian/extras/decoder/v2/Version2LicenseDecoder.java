package com.atlassian.extras.decoder.v2;

import com.atlassian.extras.common.LicenseException;
import com.atlassian.extras.common.org.springframework.util.DefaultPropertiesPersister;
import com.atlassian.extras.decoder.api.AbstractLicenseDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.apache.commons.codec.binary.Base64;

public class Version2LicenseDecoder extends AbstractLicenseDecoder {
	public static final int VERSION_NUMBER_1 = 1;
	public static final int VERSION_NUMBER_2 = 2;
	public static final int VERSION_LENGTH = 3;
	public static final int ENCODED_LICENSE_LENGTH_BASE = 31;
	public static final byte[] LICENSE_PREFIX = { 13, 14, 12, 10, 15 };
	public static final char SEPARATOR = 'X';
	private static final PublicKey PUBLIC_KEY;
	private static final int ENCODED_LICENSE_LINE_LENGTH = 76;

	static {
		try {
			String pubKeyEncoded = "AAABMA0ODAoPeNp9UMtOwzAQvPsrOMLBVZM2aXqwRJvkkJImiAAS3Lbullo4TmQ7Ffw9pi5vidNqZ2d3ZidDw7XoregUWwq7Gfgz2rPzBvUB9QXxtcjYMowf6dVq8UDrYhXTKluVpNZPoISB43KP2nQKJEk7ZYHbfA1Csv1WiiBOLoN4MuJdS0rBURm8fe2xghZZWq/X+U1aLEpSDe0Gdb27M+4SowFphs2XN6sHJPkB5ODldiANkutB8z0YzMAiC8fBjI4nNJiSVOOR9hs/yecvvdCvx+GgpGiFxS1xfpVFBYp/n4fRZDoOw2gWzedJFH1ccImURdbkFS3n0yCZxQlxDfsBSE+9d++8Ow6JsWD2o38i8ASnCyk6L/r0pYddpuKAPgiP/EnMw40F/bn8Bggsoi4wLAIULCcnUf0mUQcRuguEB9G236+5hx8CFEAC9sWyjZlLyxew3FXdIHQ/gCZVX02f7";
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			PUBLIC_KEY = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(pubKeyEncoded.getBytes())));
		} catch (NoSuchAlgorithmException e) {
			throw new Error(e);
		} catch (InvalidKeySpecException e) {
			throw new Error(e);
		}
	}

	public boolean canDecode(String licenseString) {
		licenseString = removeWhiteSpaces(licenseString);

		int pos = licenseString.lastIndexOf('X');
		if ((pos == -1) || (pos + 3 >= licenseString.length())) {
			return false;
		}
		try {
			int version = Integer.parseInt(licenseString.substring(pos + 1, pos + 3));
			if ((version != 1) && (version != 2)) {
				return false;
			}
			String lengthStr = licenseString.substring(pos + 3);
			int encodedLicenseLength = Integer.valueOf(lengthStr, 31).intValue();
			if (pos != encodedLicenseLength) {
				return false;
			}
			return true;
		} catch (NumberFormatException e) {
		}
		return false;
	}

	public Properties doDecode(String licenseString) {
		String encodedLicenseTextAndHash = getLicenseContent(removeWhiteSpaces(licenseString));
		byte[] zippedLicenseBytes = checkAndGetLicenseText(encodedLicenseTextAndHash);
		Reader licenseText = unzipText(zippedLicenseBytes);

		return loadLicenseConfiguration(licenseText);
	}

	protected int getLicenseVersion() {
		return 2;
	}

	private Reader unzipText(byte[] licenseText) {
		ByteArrayInputStream in = new ByteArrayInputStream(licenseText);
		in.skip(LICENSE_PREFIX.length);
		InflaterInputStream zipIn = new InflaterInputStream(in, new Inflater());
		try {
			return new InputStreamReader(zipIn, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new LicenseException(e);
		}
	}

	private String getLicenseContent(String licenseString) {
		String lengthStr = licenseString.substring(licenseString.lastIndexOf('X') + 3);
		try {
			int encodedLicenseLength = Integer.valueOf(lengthStr, 31).intValue();
			return licenseString.substring(0, encodedLicenseLength);
		} catch (NumberFormatException e) {
			throw new LicenseException("Could NOT decode license length <" + lengthStr + ">", e);
		}
	}

	private byte[] checkAndGetLicenseText(String licenseContent) {
		byte[] licenseText = null;
		try {
			byte[] decodedBytes = Base64.decodeBase64(licenseContent.getBytes());
			ByteArrayInputStream in = new ByteArrayInputStream(decodedBytes);
			DataInputStream dIn = new DataInputStream(in);
			int textLength = dIn.readInt();
			licenseText = new byte[textLength];
			dIn.read(licenseText);
			byte[] hash = new byte[dIn.available()];
			dIn.read(hash);
			try {
				Signature signature = Signature.getInstance("SHA1withDSA");
				signature.initVerify(PUBLIC_KEY);
				signature.update(licenseText);
				if (!signature.verify(hash)) {
					throw new LicenseException("Failed to verify the license.");
				}
			} catch (InvalidKeyException e) {
				throw new LicenseException(e);
			} catch (SignatureException e) {
				throw new LicenseException(e);
			} catch (NoSuchAlgorithmException e) {
				throw new LicenseException(e);
			}
		} catch (IOException e) {
			throw new LicenseException(e);
		}
		return licenseText;
	}

	private Properties loadLicenseConfiguration(Reader text) {
		try {
			Properties props = new Properties();
			new DefaultPropertiesPersister().load(props, text);
			return props;
		} catch (IOException e) {
			throw new LicenseException("Could NOT load properties from reader", e);
		}
	}

	private static String removeWhiteSpaces(String licenseData) {
		if ((licenseData == null) || (licenseData.length() == 0)) {
			return licenseData;
		}
		char[] chars = licenseData.toCharArray();
		StringBuffer buf = new StringBuffer(chars.length);
		for (int i = 0; i < chars.length; i++) {
			if (!Character.isWhitespace(chars[i])) {
				buf.append(chars[i]);
			}
		}
		return buf.toString();
	}

	public static String packLicense(byte[] text, byte[] hash) throws LicenseException {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			DataOutputStream dOut = new DataOutputStream(out);
			dOut.writeInt(text.length);
			dOut.write(text);
			dOut.write(hash);

			byte[] allData = out.toByteArray();
			String result = new String(Base64.encodeBase64(allData)).trim();

			result = result + 'X' + "0" + 2 + Integer.toString(result.length(), 31);
			return split(result);
		} catch (IOException e) {
			throw new LicenseException(e);
		}
	}

	private static String split(String licenseData) {
		if ((licenseData == null) || (licenseData.length() == 0)) {
			return licenseData;
		}
		char[] chars = licenseData.toCharArray();
		StringBuffer buf = new StringBuffer(chars.length + chars.length / ENCODED_LICENSE_LINE_LENGTH);
		for (int i = 0; i < chars.length; i++) {
			buf.append(chars[i]);
			if ((i > 0) && (i % ENCODED_LICENSE_LINE_LENGTH == 0)) {
				buf.append('\n');
			}
		}
		return buf.toString();
	}
}