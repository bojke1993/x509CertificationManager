package implementation;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.*;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;

import code.GuiException;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

@SuppressWarnings("deprecation")
public class MyCode extends x509.v3.CodeV3 {

	public String getSelectedKeypair() {
		return selectedKeypair;
	}

	public void setSelectedKeypair(String selectedKeypair) {
		MyCode.selectedKeypair = selectedKeypair;
	}

	private static String selectedKeypair = null;

	private static PKCS10CertificationRequest req = null;

	public static PKCS10CertificationRequest getReq() {
		return req;
	}

	public static void setReq(PKCS10CertificationRequest req) {
		MyCode.req = req;
	}

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean exportCertificate(File arg0, int arg1) {
		String alias = getSelectedKeypair();
		boolean ret = false;

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");

			ks.load(fis, "pass".toCharArray());
			Certificate cert = ks.getCertificate(alias);

			X509Certificate x509cert = (X509Certificate) cert;

			String path = arg0.getPath();

			if (path.endsWith(".cer")) {

				if (arg1 == 1) {
					Base64 enc = new Base64();
					byte[] encoded = x509cert.getEncoded();

					String pemFormat = new String(enc.encode(encoded));

					FileOutputStream fos = new FileOutputStream(arg0);

					PrintWriter pw = new PrintWriter(fos, true);

					pw.write(pemFormat);

					pw.close();
					fos.close();

					ret = true;
				} else if (arg1 == 0) {
					String derFormat = new String(x509cert.getEncoded());

					FileOutputStream fos2 = new FileOutputStream(arg0);

					PrintWriter pw2 = new PrintWriter(fos2, true);

					pw2.write(derFormat);

					pw2.close();
					fos2.close();

					ret = true;
				}

			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		boolean ret = false;

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");

			ks.load(fis, "pass".toCharArray());

			Key key = ks.getKey(arg0, "pass".toCharArray());
			Certificate[] chain = ks.getCertificateChain(arg0);

			FileOutputStream fos = new FileOutputStream(arg1);

			KeyStore expKeyStore = KeyStore.getInstance("PKCS12");

			expKeyStore.load(null, null);
			expKeyStore.setKeyEntry(arg0, key, "pass".toCharArray(), chain);

			expKeyStore.store(fos, arg2.toCharArray());

			File file = new File(arg1);

			ret = true;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public boolean generateCSR(String arg0) {

		access.enableSignButton(true);

		boolean ret = false;

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			X509Certificate x509cert = (X509Certificate) ks.getCertificate(arg0);
			PublicKey pubKey = x509cert.getPublicKey();
			PrivateKey prKey = (PrivateKey) ks.getKey(arg0, "pass".toCharArray());

			X500Name x500name = new X500Name(x509cert.getSubjectX500Principal().getName());

			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			String cnString = IETFUtils.valueToString(cn.getFirst().getValue());
			access.setSubjectCommonName(cnString);

			RDN c = x500name.getRDNs(BCStyle.C)[0];
			String cString = IETFUtils.valueToString(c.getFirst().getValue());
			access.setSubjectCountry(cString);

			RDN st = x500name.getRDNs(BCStyle.ST)[0];
			String stString = IETFUtils.valueToString(st.getFirst().getValue());
			access.setSubjectState(stString);

			RDN l = x500name.getRDNs(BCStyle.L)[0];
			String lString = IETFUtils.valueToString(l.getFirst().getValue());
			access.setSubjectLocality(lString);

			RDN org = x500name.getRDNs(BCStyle.O)[0];
			String orgString = IETFUtils.valueToString(org.getFirst().getValue());
			access.setSubjectOrganization(orgString);

			RDN ou = x500name.getRDNs(BCStyle.OU)[0];
			String ouString = IETFUtils.valueToString(ou.getFirst().getValue());
			access.setSubjectOrganizationUnit(ouString);

			PKCS10CertificationRequestBuilder reqBuilder = new JcaPKCS10CertificationRequestBuilder(x500name, pubKey);

			ContentSigner cs = new JcaContentSignerBuilder(access.getIssuerSignatureAlgorithm()).build(prKey);

			PKCS10CertificationRequest csr = reqBuilder.build(cs);
			setReq(csr);

			ret = true;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public String getIssuer(String arg0) {
		String ret = "";
		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			Certificate cert = ks.getCertificate(arg0);
			ByteArrayInputStream bis = new ByteArrayInputStream(cert.getEncoded());

			CertificateFactory cf = CertificateFactory.getInstance("x509");

			X509Certificate x509cert = (X509Certificate) cf.generateCertificate(bis);

			ret = x509cert.getIssuerX500Principal().getName();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {
		FileInputStream fis;

		String ret = "";
		try {
			fis = new FileInputStream(".\\keys\\LocalKeyStore.12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			Certificate cert = ks.getCertificate(arg0);

			ret = cert.getPublicKey().getAlgorithm();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public List<String> getIssuers(String arg0) {
		FileInputStream fis;

		List<String> ret = new ArrayList<String>();

		try {
			fis = new FileInputStream(".\\keys\\LocalKeyStore.12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			Certificate cert = ks.getCertificate(arg0);

			ByteArrayInputStream bis = new ByteArrayInputStream(cert.getEncoded());

			CertificateFactory cf = CertificateFactory.getInstance("x509");

			X509Certificate x509cert = (X509Certificate) cf.generateCertificate(bis);

			Enumeration<String> aliases = ks.aliases();

			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				try {
					Key key = ks.getKey(alias, "pass".toCharArray());
					ret.add(alias);
				} catch (UnrecoverableKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public int getRSAKeyLength(String arg0) {

		RSAPublicKey rsaPkey = null;

		int ret = 0;
		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			char[] password = "pass".toCharArray();

			try {
				KeyStore ks = KeyStore.getInstance("PKCS12");
				ks.load(fis, password);

				Certificate cert = ks.getCertificate(arg0);

				PublicKey pKey = cert.getPublicKey();

				if (pKey.getAlgorithm() == "RSA") {
					rsaPkey = (RSAPublicKey) pKey;
				}

				ret = rsaPkey.getModulus().bitCount();

			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;

	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {
		boolean ret = false;
		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			String path = arg0.getPath();

			if (arg0.getPath().endsWith(".cer")) {

				CertificateFactory fact = CertificateFactory.getInstance("X.509");

				FileInputStream newFis = new FileInputStream(path);
				BufferedInputStream bis = new BufferedInputStream(newFis);

				Certificate cert = fact.generateCertificate(bis);
				newFis.close();

				ks.setCertificateEntry(arg1, cert);

			} else {
				ret = false;
			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {

		boolean ret = false;

		String password = arg2;

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			File file = new File(arg1);

			FileInputStream path = new FileInputStream(arg1);

			KeyStore tmpKs = KeyStore.getInstance("PKCS12");
			tmpKs.load(path, password.toCharArray());

			path.close();

			Certificate cert = tmpKs.getCertificate(arg0);

			Key key = tmpKs.getKey(arg0, password.toCharArray());

			Certificate[] chain = tmpKs.getCertificateChain(arg0);

			ks.setCertificateEntry(arg0, cert);

			FileOutputStream fos = new FileOutputStream(".\\keys\\LocalKeyStore.p12");
			ks.store(fos, "pass".toCharArray());
			ret = true;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public int loadKeypair(String arg0) {
		int ret = -1;
		
		access.enableSignButton(true);
		access.enableExportButton(true);

		char[] password = "pass".toCharArray();

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");

			KeyStore tmpKs = KeyStore.getInstance("PKCS12");

			tmpKs.load(fis, "pass".toCharArray());

			Certificate cert = tmpKs.getCertificate(arg0);

			CertificateFactory cf = CertificateFactory.getInstance("x509");

			ByteArrayInputStream bis = new ByteArrayInputStream(cert.getEncoded());

			X509Certificate x509cert = (X509Certificate) cf.generateCertificate(bis);
			Key key = tmpKs.getKey(arg0, password);

			X500Name x500name = new JcaX509CertificateHolder(x509cert).getSubject();

			RDN cn = x500name.getRDNs(BCStyle.CN)[0];
			String cnString = IETFUtils.valueToString(cn.getFirst().getValue());
			access.setSubjectCommonName(cnString);

			RDN c = x500name.getRDNs(BCStyle.C)[0];
			String cString = IETFUtils.valueToString(c.getFirst().getValue());
			access.setSubjectCountry(cString);

			RDN st = x500name.getRDNs(BCStyle.ST)[0];
			String stString = IETFUtils.valueToString(st.getFirst().getValue());
			access.setSubjectState(stString);

			RDN l = x500name.getRDNs(BCStyle.L)[0];
			String lString = IETFUtils.valueToString(l.getFirst().getValue());
			access.setSubjectLocality(lString);

			RDN org = x500name.getRDNs(BCStyle.O)[0];
			String orgString = IETFUtils.valueToString(org.getFirst().getValue());
			access.setSubjectOrganization(orgString);

			RDN ou = x500name.getRDNs(BCStyle.OU)[0];
			String ouString = IETFUtils.valueToString(ou.getFirst().getValue());
			access.setSubjectOrganizationUnit(ouString);

			String signAlg = x509cert.getSigAlgName();
			access.setSubjectSignatureAlgorithm(signAlg);

			setSelectedKeypair(arg0);
			

			if (x509cert.getSignature() != null) {
				ret = 1;
				if (tmpKs.isKeyEntry(arg0)) {
					ret = 2;
				}
			} else {
				ret = 0;
			}

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {

			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {

		char[] password = "pass".toCharArray();

		Enumeration<String> ret = null;

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore\\.p12");

			try {
				KeyStore ks = KeyStore.getInstance("PKCS12");

				ks.load(fis, password);

				ret = ks.aliases();

			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			fis.close();

		} catch (FileNotFoundException e) {
			// keystore ne postoji

			File dir = new File(".\\keys");

			if (!dir.exists()) {
				dir.mkdirs();
			}

			try {
				KeyStore ks = KeyStore.getInstance("PKCS12");

				ks.load(null, null);

				FileOutputStream fos = new FileOutputStream(".\\keys\\LocalKeyStore.p12");
				ks.store(fos, password);
				fos.close();

				ret = ks.aliases();

			} catch (KeyStoreException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (CertificateException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ret;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		boolean ret = false;

		FileInputStream fis;
		try {
			fis = new FileInputStream(".\\keys\\LocalKeyStore\\.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			ks.deleteEntry(arg0);

			ret = true;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore\\.p12");

			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			Enumeration<String> aliases = ks.aliases();

			for (Enumeration<String> e = aliases; e != null && e.hasMoreElements();) {
				ks.deleteEntry(e.nextElement());
			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean saveKeypair(String arg0) {
		boolean ret = false;
		try {

			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			
			

			// generisanje para kljuceva
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			String serialNum = access.getSerialNumber();
			int version = access.getVersion();

			BigInteger sn = new BigInteger(serialNum);
			Date dateFrom = access.getNotBefore();
			Date dateUntil = access.getNotAfter();

			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

			nameBuilder.addRDN(BCStyle.C, access.getSubjectCountry());
			nameBuilder.addRDN(BCStyle.ST, access.getSubjectState());
			nameBuilder.addRDN(BCStyle.L, access.getSubjectLocality());
			nameBuilder.addRDN(BCStyle.O, access.getSubjectOrganization());
			nameBuilder.addRDN(BCStyle.OU, access.getSubjectOrganizationUnit());
			nameBuilder.addRDN(BCStyle.CN, access.getSubjectCommonName());

			X500Name certName = nameBuilder.build();

			PublicKey pk = keyPair.getPublic();
			byte[] encoded = pk.getEncoded();
			SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));

			String signAlg = access.getPublicKeySignatureAlgorithm();
			PrivateKey prKey = keyPair.getPrivate();
			ContentSigner signiture = null;
			signiture = new JcaContentSignerBuilder(signAlg).build(prKey);

			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(certName, sn, dateUntil, dateUntil,
					certName, pk);
			
			/*
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal              subjectName = new X500Principal("CN=Test V3 Certificate");
			 
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(caCert.getSubjectX500Principal());
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(subjectName);
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm(signatureAlgorithm);
			 
			certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
			                        new AuthorityKeyIdentifierStructure(caCert));
			certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
			                        new SubjectKeyIdentifierStructure(keyPair.getPublic());
			 
			X509Certificate cert = certGen.generate(caKey, "BC"); 
			
			

			
			 * certBuilder.addExtension(Extension.certificatePolicies,
			 * access.isCritical(2), new
			 * ASN1ObjectIdentifier(access.getCpsUri()));
			 * certBuilder.addExtension(Extension.issuerAlternativeName,
			 * access.isCritical(4), new
			 * ASN1ObjectIdentifier(access.getIssuer()));
			 * 
			 * if(access.isCA()){ int length =
			 * Integer.parseInt(access.getPathLen());
			 * certBuilder.addExtension(Extension.basicConstraints,
			 * access.isCritical(6), new BasicConstraints(length)); } else{
			 * certBuilder.addExtension(Extension.basicConstraints,
			 * access.isCritical(6), new BasicConstraints(false)); }
			 */

			X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signiture));
			

			byte[] enc = signedCert.getEncoded();

			Certificate cert = (Certificate) signedCert;

			KeyStore ks = KeyStore.getInstance("PKCS12");

			ks.load(fis, "pass".toCharArray());
			
			ks.setCertificateEntry(arg0, signedCert);
			
			FileOutputStream fos = new FileOutputStream(".\\keys\\LocalKeyStore.p12");
			ks.store(fos, "pass".toCharArray());

			Certificate test = ks.getCertificate(arg0);

			fis.close();
			
			ret = true;

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ret;

	}

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		if(generateCSR(getSelectedKeypair()) == true){
			PKCS10CertificationRequest req = this.getReq();
		}
	
		boolean ret = false;
		
		

		try {
			FileInputStream fis = new FileInputStream(".\\keys\\LocalKeyStore.p12");
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, "pass".toCharArray());

			PrivateKey prKey = (PrivateKey) ks.getKey(arg0, "pass".toCharArray());

			X500Name name = req.getSubject();
			SubjectPublicKeyInfo pkInfo = req.getSubjectPublicKeyInfo();

			Date notBefore = access.getNotBefore();
			Date notAfter = access.getNotAfter();
			BigInteger serialNumber = new BigInteger(access.getSerialNumber());

			X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(name, serialNumber, notAfter, notAfter,
					null, name, pkInfo);

			try {
				ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeySignatureAlgorithm())
						.build(prKey);
				X509CertificateHolder signedCertHolder = certBuilder.build(signer);
				X509Certificate signedCert = new JcaX509CertificateConverter().getCertificate(signedCertHolder);

				ret = true;
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ret;
	}

}
