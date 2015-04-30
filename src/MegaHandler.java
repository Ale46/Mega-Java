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
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;


import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;




public class MegaHandler {

	private String email, password, sid;
	private int sequence_number;
	private long[] master_key;
	private BigInteger[] rsa_private_key;
	private long[] password_aes;
	HashMap<String,long[]> user_keys = new HashMap<String,long[]>();

	public MegaHandler(String email, String password) {
		this.email = email;
		this.password = password;
		Random rg = new Random();
		sequence_number = rg.nextInt(Integer.MAX_VALUE);
	}

	public int login() throws IOException {

		password_aes = MegaCrypt.prepare_key_pw(password);
		String uh = MegaCrypt.stringhash(email, password_aes);

		JSONObject json = new JSONObject();
		try {
			json.put("a", "us");
			json.put("user", email);
			json.put("uh", uh);
		} catch (JSONException e) {
			e.printStackTrace();
		}

		while (true) {
			String response = api_request(json.toString());

			if (isInteger(response))
				return Integer.parseInt(response);

			try {
				if (login_process(new JSONObject(response), password_aes) != -2) {
					break;
				}
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}

		return 0;
	}

	private int login_process(JSONObject json, long[] password_aes) throws IOException {

		String master_key_b64 = null;
		try {
			master_key_b64 = json.getString("k");
		} catch (JSONException e) {
			e.printStackTrace();
		}
		if (master_key_b64 == null || master_key_b64.isEmpty())
			return -1;

		long[] encrypted_master_key = MegaCrypt.base64_to_a32(master_key_b64);
		master_key = MegaCrypt.decrypt_key(encrypted_master_key, password_aes);

		if (json.has("csid")) {
			String encrypted_rsa_private_key_b64 = null;
			try {
				encrypted_rsa_private_key_b64 = json.getString("privk");
			} catch (JSONException e) {
				e.printStackTrace();
			}

			long[] encrypted_rsa_private_key = MegaCrypt.base64_to_a32(encrypted_rsa_private_key_b64);
			long[] rsa_private_key = MegaCrypt.decrypt_key(encrypted_rsa_private_key, master_key);
			String private_key = MegaCrypt.a32_to_str(rsa_private_key);

			this.rsa_private_key = new BigInteger[4];
			for (int i = 0; i < 4; i++) {
				int l = ((((int) private_key.charAt(0)) * 256 + ((int) private_key.charAt(1)) + 7) / 8) + 2;
				this.rsa_private_key[i] = MegaCrypt.mpi_to_int(private_key.substring(0, l));
				private_key = private_key.substring(l);
			}

			BigInteger encrypted_sid = null;
			try {
				encrypted_sid = MegaCrypt.mpi_to_int(MegaCrypt.base64_url_decode(json.getString("csid")));
			} catch (JSONException e) {
				e.printStackTrace();
			}

			BigInteger modulus = this.rsa_private_key[0].multiply(this.rsa_private_key[1]);
			BigInteger privateExponent = this.rsa_private_key[2];

			BigInteger sid = null;
			try {
				PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
				Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
				cipher.init(Cipher.DECRYPT_MODE, privateKey);
				// PyCrypt can handle >256 bit length... what the fuck... sometimes i get 257
				if (encrypted_sid.toByteArray().length > 256) {
					Random rg = new Random();
					sequence_number = rg.nextInt(Integer.MAX_VALUE);
					return -2;  // lets get a new seession
				}
				sid = new BigInteger(cipher.doFinal(encrypted_sid.toByteArray()));
			} catch (Exception e) {
				e.printStackTrace();
				return -1;
			}

			String sidS = sid.toString(16);
			if (sidS.length() % 2 != 0)
				sidS = "0" + sidS;
			try {
				byte[] sidsnohex = MegaCrypt.decodeHexString(sidS);
				this.sid = MegaCrypt.base64_url_encode(new String(sidsnohex, "ISO-8859-1").substring(0, 43));
			} catch (Exception e) {
				e.printStackTrace();
				return -1;
			}
		}
		return 0;
	}

	public String add_user(String email) {
		JSONObject json = new JSONObject();
		try {
			json.put("a", "ur");
			json.put("u", email);
			json.put("l", 1);
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return api_request(json.toString());
	}
	
	public long get_quota() throws JSONException {
		JSONObject json = new JSONObject();
		try {
			json.put("a", "uq");
			json.put("xfer", 1);
			
		} catch (JSONException e) {
			e.printStackTrace();
		}

		return new JSONObject(api_request(json.toString())).getLong("mstrg");
	}

	public String get_user() {
		JSONObject json = new JSONObject();
		try {
			json.put("a", "ug");
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return api_request(json.toString());
	}


	public ArrayList<MegaFile> get_files() throws UnsupportedEncodingException {
		JSONObject json = new JSONObject();
		try {
			json.put("a", "f");
			json.put("c", "1");

		} catch (JSONException e) {
			e.printStackTrace();
		}

		String files = api_request(json.toString());
		// TODO check for negativ error
		//print(json.toString());
		ArrayList<MegaFile> megaFiles = new ArrayList<MegaFile>();

		JSONArray array = null;
		try {
			json = new JSONObject(files);
			array = json.getJSONArray("f");
			for (int i = 0; i < array.length(); i++) {
				//print(array.get(i).toString());
				megaFiles.add(process_file(new JSONObject(array.get(i).toString())));

			}
		} catch (JSONException e) {
			e.printStackTrace();
			return null;
		}
		return megaFiles;
	}


	private MegaFile process_file(JSONObject jsonFile) throws UnsupportedEncodingException {

		MegaFile file = new MegaFile();
		try {

			if (jsonFile.getInt("t") < 2) {
				
				String key = "";
				String uid = jsonFile.getString("u");
				String h =(jsonFile.getString("h"));
				file.setUID(uid);
				file.setHandle(h);
				//print (h);
				if (jsonFile.getString("k").contains("/")){
					String[] keys = jsonFile.getString("k").split("/");
					int start = keys[0].indexOf(":")+1;
					key = keys[0].substring(start);

				}

				String attributes = MegaCrypt.base64_url_decode(jsonFile.getString("a"));
				
				long[] k = new long[4];
				if (!key.isEmpty()){
					long[] keys_a32 = MegaCrypt.decrypt_key(MegaCrypt.base64_to_a32(key), master_key);
					if (jsonFile.getInt("t") == 0) {

						k[0] = keys_a32[0] ^ keys_a32[4];
						k[1] = keys_a32[1] ^ keys_a32[5];
						k[2] = keys_a32[2] ^ keys_a32[6];
						k[3] = keys_a32[3] ^ keys_a32[7];


					} else {
						k[0] = keys_a32[0];
						k[1] = keys_a32[1];
						k[2] = keys_a32[2];
						k[3] = keys_a32[3];
						file.setDirectory(true);

					}
					
					file.setKey(k);
					file.setAttributes(MegaCrypt.decrypt_attr(attributes, k));
				}else if(!jsonFile.isNull("su") && !jsonFile.isNull("sk") && jsonFile.getString("k").contains(":")){
					long[] keyS;

					user_keys.put(jsonFile.getString("u"), MegaCrypt.decrypt_key(MegaCrypt.base64_to_a32(jsonFile.getString("sk")), master_key));
					//print("ShareKey->"+jsonFile.getString("sk"));
					int dd1 = jsonFile.getString("k").indexOf(':');
					String sk = jsonFile.getString("k").substring(dd1 + 1);

					keyS = MegaCrypt.decrypt_key(MegaCrypt.base64_to_a32(sk) ,user_keys.get(jsonFile.getString("u")));
					if (jsonFile.getInt("t") == 0){
						long[]  keys_a32S = keyS;
						k[0] = keys_a32S[0] ^ keys_a32S[4];
						k[1] = keys_a32S[1] ^ keys_a32S[5];
						k[2] = keys_a32S[2] ^ keys_a32S[6];
						k[3] = keys_a32S[3] ^ keys_a32S[7];
					}else{
						k = keyS;
						file.setDirectory(true);
					}
					
					file.setKey(k);
					file.setAttributes(MegaCrypt.decrypt_attr(attributes, k));

				}else if (!jsonFile.isNull("u") && jsonFile.getString("k").contains(":") && user_keys.containsKey(jsonFile.getString("u"))) {

					int dd1 = jsonFile.getString("k").indexOf(':');
					String sk = jsonFile.getString("k").substring(dd1 + 1);
					//print(user_keys.get(jsonFile.getString("u")));
					long[] keyS = MegaCrypt.decrypt_key(MegaCrypt.base64_to_a32(sk) ,user_keys.get(jsonFile.getString("u")));
					if (jsonFile.getInt("t") == 0){
						long[]  keys_a32S = keyS;
						k[0] = keys_a32S[0] ^ keys_a32S[4];
						k[1] = keys_a32S[1] ^ keys_a32S[5];
						k[2] = keys_a32S[2] ^ keys_a32S[6];
						k[3] = keys_a32S[3] ^ keys_a32S[7];
					}else{
						k = keyS;
						file.setDirectory(true);
					}
					
					file.setKey(k);
					file.setAttributes(MegaCrypt.decrypt_attr(attributes, k));
					
				}else if (!jsonFile.isNull("k")){
					int dd1 = jsonFile.getString("k").indexOf(':');
					key = jsonFile.getString("k").substring(dd1 + 1);
					long[] keys_a32S = MegaCrypt.decrypt_key(MegaCrypt.base64_to_a32(key), master_key);
					if (jsonFile.getInt("t") == 0){

						k[0] = keys_a32S[0] ^ keys_a32S[4];
						k[1] = keys_a32S[1] ^ keys_a32S[5];
						k[2] = keys_a32S[2] ^ keys_a32S[6];
						k[3] = keys_a32S[3] ^ keys_a32S[7];
						file.setDirectory(true);
						
						
					}/*else{
						k = keys_a32S;

						file.setDirectory(true);

					}*/
					file.setKey(k);
					
					file.setAttributes(MegaCrypt.decrypt_attr(attributes, k));
				}else{
					file.setAttributes(jsonFile.toString());
				}

			} else if (jsonFile.getInt("t") == 2) {
				file.setName("Cloud Drive");
			} else if (jsonFile.getInt("t") == 3) {
				file.setName("Cloud Inbox");
			} else if (jsonFile.getInt("t") == 4) {
				file.setName("Rubbish Bin");
			} else {
				file.setName(jsonFile.toString());
			}
			return file;
		} catch (JSONException e) {
			e.printStackTrace();
		}

		//file.setAttributes(jsonFile.toString());
		return file;
	}

	public String get_url(MegaFile f){
		
		if ( f.getHandle() == null ||  f.getKey() == null)
			return "Error";
		JSONObject json = new JSONObject();
		try {
			json.put("a", "l");
			json.put("n", f.getHandle());

		} catch (JSONException e) {
			e.printStackTrace();
		}

		String public_handle = api_request(json.toString());
		if (public_handle.equals("-11"))
			return "Shared file, no public url";
		return "https://mega.co.nz/#!"+public_handle.substring(1, public_handle.length()-1)+"!"+MegaCrypt.a32_to_base64(f.getKey());
		
	}

	private String api_request(String data) {
		HttpURLConnection connection = null;
		try {
			String urlString = "https://g.api.mega.co.nz/cs?id=" + sequence_number;
			if (sid != null)
				urlString += "&sid=" + sid;

			URL url = new URL(urlString);
			connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("POST"); //use post method
			connection.setDoOutput(true); //we will send stuff
			connection.setDoInput(true); //we want feedback
			connection.setUseCaches(false); //no caches
			connection.setAllowUserInteraction(false);
			connection.setRequestProperty("Content-Type", "text/xml");

			OutputStream out = connection.getOutputStream();
			try {
				OutputStreamWriter wr = new OutputStreamWriter(out);
				wr.write("[" + data + "]"); //data is JSON object containing the api commands
				wr.flush();
				wr.close();
			} catch (IOException e) {
				e.printStackTrace();
			} finally { //in this case, we are ensured to close the output stream
				if (out != null)
					out.close();
			}

			InputStream in = connection.getInputStream();
			StringBuffer response = new StringBuffer();
			try {
				BufferedReader rd = new BufferedReader(new InputStreamReader(in));
				String line = "";
				while ((line = rd.readLine()) != null) {
					response.append(line);
				}
				rd.close(); //close the reader
			} catch (IOException e) {
				e.printStackTrace();
			} finally {  //in this case, we are ensured to close the input stream
				if (in != null)
					in.close();
			}

			return response.toString().substring(1, response.toString().length() - 1);


		} catch (IOException e) {
			e.printStackTrace();
		}

		return "";
	}

	public static boolean isInteger(String string) {
		if (string == null || string.isEmpty()) {
			return false;
		}
		int length = string.length();
		int i = 0;
		if (string.charAt(i) == '[') {
			if (length == 1)
				return false;
			i++;
		}
		if (string.charAt(i) == '-') {
			if (length == 1 + i)
				return false;
			i++;
		}
		for (; i < length; i++) {
			char c = string.charAt(i);
			if (c <= '/' || c >= ':') {
				return false;
			}
		}
		return true;
	}



	public void download(String url) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, JSONException, BadPaddingException, InvalidKeyException {
		download(url, new File(".").getCanonicalPath(), false);
	}

	public void download(String url, String path) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, JSONException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		download(url, path, false);
	}

	public void download_verbose(String url, String path) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, JSONException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		download(url, path, true);
	}

	public void download_verbose(String url) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, JSONException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
		download(url, new File(".").getCanonicalPath(), true);
	}


	private void download(String url, String path, boolean verbose) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, JSONException {
		//TODO DOWNLOAD mismatch?
		print("Download started");
		String[] s = url.split("!");
		String file_id = s[1];
		byte[] file_key = MegaCrypt.base64_url_decode_byte(s[2]); 

		int[] intKey = MegaCrypt.aByte_to_aInt(file_key);
		JSONObject json = new JSONObject();
		try {
			json.put("a", "g");
			json.put("g", "1");
			json.put("p", file_id);
		} catch (JSONException e) {
			e.printStackTrace();
		}
		
		JSONObject file_data = new JSONObject(api_request(json.toString()));
		//print(file_data);
		int[] keyNOnce = new int[] { intKey[0] ^ intKey[4], intKey[1] ^ intKey[5], intKey[2] ^ intKey[6], intKey[3] ^ intKey[7], intKey[4], intKey[5] };
		byte[] key = MegaCrypt.aInt_to_aByte(keyNOnce[0], keyNOnce[1], keyNOnce[2], keyNOnce[3]);

		int[] iiv = new int[] { keyNOnce[4], keyNOnce[5], 0, 0 };
		byte[] iv = MegaCrypt.aInt_to_aByte(iiv);

		@SuppressWarnings("unused")
		int file_size = file_data.getInt("s");
		String attribs = (file_data.getString("at"));

		attribs = new String(MegaCrypt.aes_cbc_decrypt(MegaCrypt.base64_url_decode_byte(attribs), key));
		//print(attribs.substring(4, attribs.length()));

		String file_name = new JSONObject(attribs.substring(4, attribs.length())).getString("n");
		//print("Filename->>" +file_name);
		final IvParameterSpec ivSpec = new IvParameterSpec(iv);
		final SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/nopadding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
		InputStream is = null;
		String file_url = null;
		try {
			file_url = file_data.getString("g");
		} catch (JSONException e) {
			e.printStackTrace();
		}

		FileOutputStream fos = new FileOutputStream(path + File.separator + file_name);
		final OutputStream cos = new CipherOutputStream(fos, cipher);
		final Cipher decipher = Cipher.getInstance("AES/CTR/NoPadding");
	    decipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
		int read = 0;
		final byte[] buffer = new byte[32767];
		try {

			URLConnection urlConn = new URL(file_url).openConnection();

            ProgressBar bar = new ProgressBar();
			//print(file_url);
            if(verbose) bar.update(0, file_size, "");
			//print("FILESIZE:" +file_size);
			is = urlConn.getInputStream();
			long mDownloaded = 0;
			double current_speed;
			long startTime = System.nanoTime();
			final double NANOS_PER_SECOND = 1000000000.0;
			final double BYTES_PER_MIB = 1024 * 1024;
			while ((read = is.read(buffer,0, 1024)) > 0) {
				cos.write(buffer, 0, read);
				mDownloaded += read;
				//print(mDownloaded);
				long timeInSecs = (System.nanoTime() - startTime + 1);
				//print("Debug:" + mDownloaded + "/" + timeInSecs);
				current_speed = NANOS_PER_SECOND / BYTES_PER_MIB * mDownloaded / (timeInSecs);
				//print("Speed: "+ (current_speed) + " Mbps");
				if(verbose) bar.update(mDownloaded, file_size, String.format("%.2f", current_speed) + " Mbps");
			}
		} finally {
			try {
				cos.close();
				if (is != null) {
					is.close();
				}
			} finally {
				if (fos != null) {
					fos.close();
				}
			}
		}
		print("Download finished");
	}



	public static void print(Object o) {
		System.out.println(o);
	}
	class ProgressBar {
		private StringBuilder progress;

		/**
		 * initialize progress bar properties.
		 */
		public ProgressBar() {
			init();
		}

		/**
		 * called whenever the progress bar needs to be updated.
		 * that is whenever progress was made.
		 *
		 * @param done an int representing the work done so far
		 * @param total an int representing the total work
		 */
		public void update(double done, double total, String append) {
			char[] workchars = {'|', '/', '-', '\\'};
			String format = "\r%3d%% %s %c %s";

			int percent = (int)((++done * 100) / total);
			int extrachars = (percent / 2) - this.progress.length();

			while (extrachars-- > 0) {
				progress.append("#");
			}

			System.out.printf(format, percent, progress, workchars[(int)done % workchars.length], append);

			if (done >= total) {
				System.out.flush();
				System.out.println();
				init();
			}
		}

		private void init() {
			this.progress = new StringBuilder(60);
		}
	}
}
