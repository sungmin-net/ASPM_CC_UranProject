package kr.ac.snu.mmlab.apm.controlcenter;

import static kr.ac.snu.mmlab.apm.controlcenter.ApmEnums.*;

import java.io.File;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ApmAdminMain {

    static final String UID = "CC1"; // TODO rc?

    static final String KEYSTORE_PASS = "mmlabmmlab"; // TODO apply timestamp based HMAC protection

    private static final String MAGIC = "APM";
    private static final String POLICY_DIR_PREFIX = MAGIC + "_P";

    static final SimpleDateFormat VERSION_FORMAT = new SimpleDateFormat("yyMMddHHmmss");

    // member variables
    private static List<String> mTargetList = new ArrayList<>();
    private static Date mBegin = new Date();
    private static Date mExpiry = new Date(4102412399000l); // 2099.12.31 23:59:59
    private static double mLatitude = 0.0;
    private static double mLongitude = 0.0;
    private static double mRadius = 100;
    private static double mAltitude = 500;
    private static String mVersion = null;
    private static JSONArray mCurPolicy = null;
    private static JSONArray mPrevManifest = null;
    private static KeyStore mKeyStore = null;

    // Note. add APM policies if needed and available
    static boolean mSetCameraDisabled = false;
    static boolean mSetMasterVolumeMuted = false;
    static boolean mSetUamWindowsBlurred = false;

    public static void main(String[] args) throws Exception {
        System.out.println("# Aerial Privacy Management (APM) administrator starting.");

        Security.addProvider(new BouncyCastleProvider());

        Scanner reader = new Scanner(System.in);
        String[] buf = null;

        // Note. issuer will be written when save
        // 1. Who
        System.out.print("# Enter the policy target UID(s). If multiple, use comma to split."
                + "\nDefault target is \"ALL\": ");
        buf = reader.nextLine().split(",");
        if (buf.length == 1 && "".equals(buf[0])) { // default
            mTargetList.add("ALL");
        } else {
            for (String target : buf) {
                mTargetList.add(target.trim());
            }
        }

        // 2. When
        System.out.print("# Enter the policy begin and expired time as YYMMDDHHMMSS YYMMDDHHMMSS"
                + "(ex. 210105145520 220105145520).\nDefault is from now to 2099.12.31 : ");
        buf = reader.nextLine().split(" ");
        if (buf.length == 1 && "".equals(buf[0])) { // default
            // do nothing
        } else {
            if (buf.length != 2) {
                exitWithErrMsg("Two YYMMDDHHMMSS type arguments are required");
            }

            mBegin = VERSION_FORMAT.parse(buf[0].trim());
            mExpiry = VERSION_FORMAT.parse(buf[1].trim());

            Date now = new Date();
            if (mBegin.before(now)) {
                exitWithErrMsg("Begin time must be future.:" + VERSION_FORMAT.format(mBegin));
            }

            if (mExpiry.before(now)) {
                exitWithErrMsg("Expired time must be future.:" + VERSION_FORMAT.format(mExpiry));
            }

            if (mBegin.after(mExpiry)) {
                exitWithErrMsg("Begin time must before expired time:" + Arrays.deepToString(buf));
            }
        }

        // 3. Where - GPS coordinates(latitude, longitude), radius, and altitude(upper-bound)
        System.out.print("# Enter the center point of policy valid area as GPS coordinate"
                + "(ex. 1.111 2.222).\nDefault is everywhere: ");
        buf = reader.nextLine().split(" ");
        if (buf.length == 1 && "".equals(buf[0])) { // default
            // do nothing
        } else {
            mLatitude = Double.parseDouble(buf[0]);
            mLongitude = Double.parseDouble(buf[1]);

            if (mLatitude <= -90 || mLatitude > 90) {
                exitWithErrMsg("Latitude of GPS coordinate must be in -90.0 ~ 89.999...");
            }

            if (mLongitude <= -180 || mLongitude > 180) {
                exitWithErrMsg("Longitude of GPS coordinate must be in -180.0 ~ 179.999...");
            }

            System.out.print("# Enter the meter unit radius and upper-bound altitude."
                    + "(ex. 1.111 200.222).\nDefault is 100 500 : ");
            buf = reader.nextLine().split(" ");
            if (buf.length == 1 && "".equals(buf[0])) {
                // do nothing
            } else {
                mRadius = Double.parseDouble(buf[0]);
                mAltitude = Double.parseDouble(buf[1]);

                if (mRadius < 0) {
                    exitWithErrMsg("The radius must be > 0");
                }
                if (mAltitude <= 0) {
                    exitWithErrMsg("The altitude must be => 0");
                }
            }
        }

        // 4. What & How - APM policies. Add more APM policy if needed
        System.out.print("# Will the camera be disallowed?[y/n]\nDefault is no: ");
        buf[0] = reader.nextLine().toLowerCase();

        if ("".equals(buf[0])) { // default
            // Do nothing
        } else {
            if ("yes".equals(buf[0]) || "y".equals(buf[0])) {
                mSetCameraDisabled = true;
            } else if("no".equals(buf[0]) || "n".equals(buf[0])) {
                // Do nothing
            } else {
                exitWithErrMsg("Invalid input for the camera policy.");
            }
        }

        System.out.print("# Will the audio be muted?[y/n]\nDefault is no: ");
        buf[0] = reader.nextLine().toLowerCase();

        if ("".equals(buf[0])) { // default
            // Do nothing
        } else {
            if ("yes".equals(buf[0]) || "y".equals(buf[0])) {
                mSetMasterVolumeMuted = true;
            } else if ("no".equals(buf[0]) || "n".equals(buf[0])) {
                // Do nothing
            } else {
                exitWithErrMsg("Invalid input for the master volume policy");
            }
        }

        System.out.print("# Will the windows of the UAM be blurred?[y/n]\nDefault is no: ");
        buf[0] = reader.nextLine().toLowerCase();

        if ("".equals(buf[0])) { // default
            // Do nothing
        } else {
            if ("yes".equals(buf[0]) || "y".equals(buf[0])) {
                mSetUamWindowsBlurred = true;
            } else if ("no".equals(buf[0]) || "n".equals(buf[0])) {
                // Do nothing
            } else {
                exitWithErrMsg("Invalid input for the master volume policy");
            }
        }

        loadKeystore();
        loadParentManifest();

        savePolicy();
        generateManifest();
        dropX509Cert();

        System.out.println("# New APM policy issued: " + POLICY_DIR_PREFIX + mVersion);
    }

    private static void loadParentManifest() throws IOException {
        // find latest policy
        File curDir = new File(System.getProperty("user.dir"));
        long latestVersion = Long.MIN_VALUE;
        for (File file : curDir.listFiles()) {
            if (file.getName().startsWith(POLICY_DIR_PREFIX) && file.isDirectory()) {
                long version = Long.parseLong(file.getName().replace(POLICY_DIR_PREFIX, ""));
                latestVersion = Math.max(version, latestVersion);
            }
        }

        if (latestVersion == Long.MIN_VALUE) {
            return; // do nothing if current policy is the first policy
        }

        String parentManifestPath = POLICY_DIR_PREFIX + latestVersion + "\\" + "manifest.json";

        String jsonText = new String(Files.readAllBytes(Paths.get(parentManifestPath)));
        mPrevManifest = new JSONArray(jsonText);
    }

    private static void dropX509Cert() throws CertificateEncodingException, KeyStoreException,
            IOException {
        String certPath = POLICY_DIR_PREFIX + mVersion + "\\" + "x509cert.pem";
        File cert = new File(certPath);
        if (!cert.getParentFile().exists()) {
            exitWithErrMsg("# APM policy generation failed because policy path doesn't exist.");
        }

        StringBuffer buf = new StringBuffer();
        buf.append("-----BEGIN CERTIFICATE-----\n");

        byte[] blob = mKeyStore.getCertificate(MAGIC + "_" + UID).getEncoded();
        String encodedCertStr = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(blob);
        buf.append(encodedCertStr);
        buf.append("\n-----END CERTIFICATE-----");

        Files.write(Paths.get(certPath), buf.toString().getBytes());

        System.out.println("# X.509 cert is dropped.");
    }

    private static void loadKeystore() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException {
        mKeyStore = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(new File("APM_" + UID + ".p12"));
        mKeyStore.load(fis, KEYSTORE_PASS.toCharArray());
    }


    private static void generateManifest() throws UnrecoverableKeyException, InvalidKeyException,
            JSONException, KeyStoreException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, IOException {
        JSONArray curManifest = new JSONArray();

        JSONArray metadata = new JSONArray();

        // version
        metadata.put(new JSONObject().put(ApmEnums.Metadata.Version.toString(), mVersion));

        // fingerprint
        metadata.put(new JSONObject().put(ApmEnums.Metadata.Fingerprint.toString(),
                getFingerprint()));

        // previous version
        metadata.put(new JSONObject().put(ApmEnums.Metadata.PrevVersion.toString(),
                getPrevVersion()));

        // previous fingerprint
        metadata.put(new JSONObject().put(ApmEnums.Metadata.PrevFingerprint.toString(),
                getPrevFingerprint()));

        curManifest.put(new JSONObject().put(ApmEnums.Manifest.Metadata.toString(), metadata));

        // signature
        curManifest.put(new JSONObject().put(ApmEnums.Manifest.Signature.toString(),
                getSign(metadata.toString())));

        String manifestPath = POLICY_DIR_PREFIX + mVersion + "\\manifest.json";
        File manifest = new File(manifestPath);
        if (!manifest.getParentFile().exists()) {
            exitWithErrMsg("# APM policy generation failed because policy path doesn't exist.");
        }

        Files.write(Paths.get(manifestPath), curManifest.toString(4/* indentation */).getBytes());

        System.out.println("# APM manifest file saved: " + manifestPath);
        System.out.println(curManifest.toString(4));

    }

    private static String getPrevVersion() {
        if (mPrevManifest != null) {
            JSONArray prevMetadata = mPrevManifest.getJSONObject(Manifest.Metadata.ordinal())
                    .getJSONArray(Manifest.Metadata.toString());
            return prevMetadata.getJSONObject(Metadata.Version.ordinal()).getString(
                    Metadata.Version.toString());
        }
        return "0"; // Do not return null to leave the key of json object
    }


    private static String getPrevFingerprint() {
        if (mPrevManifest != null) {
            JSONArray prevMetadata = mPrevManifest.getJSONObject(Manifest.Metadata.ordinal())
                    .getJSONArray(Manifest.Metadata.toString());
            return prevMetadata.getJSONObject(Metadata.Fingerprint.ordinal()).getString(
                    Metadata.Fingerprint.toString());
        }
        return "0"; // Do not return null to leave the key of json object
    }

    static String getSign(String toBeSigned) throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
                SignatureException, UnsupportedEncodingException {
        PrivateKey privKey = (PrivateKey) mKeyStore.getKey(MAGIC + "_" + UID,
                KEYSTORE_PASS.toCharArray());

        Signature signer = Signature.getInstance("SHA256withRSA/PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32, 1));
        signer.initSign(privKey);
        signer.update(toBeSigned.getBytes("UTF8"));
        byte[] signBytes = signer.sign();

        return Base64.getEncoder().encodeToString(signBytes);
    }

    private static String getFingerprint() throws NoSuchAlgorithmException {
        // Note. fingerprint is sha256 hashed Base64 string
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(mCurPolicy.toString().getBytes()); // Note. do not add json indentation
        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static void savePolicy() throws JSONException, IOException {
        // prepare json object
        mCurPolicy = new JSONArray();

        // issuer
        mCurPolicy.put(new JSONObject().put(Policy.Issuer.toString(), UID));

        // version
        Date versionDate = new Date();
        mVersion = VERSION_FORMAT.format(versionDate);
        mCurPolicy.put(new JSONObject().put(Policy.Version.toString(), mVersion));

        // target
        mCurPolicy.put(new JSONObject().put(Policy.Target.toString(),
                new JSONArray(mTargetList)));

        // period
        // Note. "Begin" should be after or same with version which means issued time
        if (mBegin.before(versionDate)) {
            mCurPolicy.put(new JSONObject().put(Policy.Begin.toString(), mVersion));
        } else {
            mCurPolicy.put(new JSONObject().put(Policy.Begin.toString(),
                    VERSION_FORMAT.format(mBegin)));
        }
        mCurPolicy.put(new JSONObject().put(Policy.Until.toString(),
                VERSION_FORMAT.format(mExpiry)));

        // where
        mCurPolicy.put(new JSONObject().put(Policy.Latitude.toString(),
                String.format("%.6f", mLatitude)));
        mCurPolicy.put(new JSONObject().put(Policy.Longitude.toString(),
                String.format("%.6f", mLongitude)));
        mCurPolicy.put(new JSONObject().put(Policy.Altitude.toString(),
                String.format("%.6f", mAltitude)));
        mCurPolicy.put(new JSONObject().put(Policy.Radius.toString(),
                String.format("%.6f", mRadius)));

        // what & how
        JSONArray restrictions = new JSONArray();
        restrictions.put(new JSONObject().put(Restriction.SetCameraDisabled.toString(),
                mSetCameraDisabled));
        restrictions.put(new JSONObject().put(Restriction.SetMasterVolumeMuted.toString(),
                mSetMasterVolumeMuted));
        restrictions.put(new JSONObject().put(Restriction.SetUamWindowBlurred.toString(),
                mSetUamWindowsBlurred));
        mCurPolicy.put(new JSONObject().put(Policy.Restriction.toString(), restrictions));

        String policyPath = POLICY_DIR_PREFIX + mVersion + "\\policy.json";
        File policy = new File(policyPath);
        if (policy.getParentFile().exists()) {
            exitWithErrMsg("# Policy generation failed due to duplicated version");
        }
        policy.getParentFile().mkdir();
        Files.write(Paths.get(policyPath), mCurPolicy.toString(4).getBytes());
        System.out.println("# APM policy file saved: " + policyPath);
        System.out.println(mCurPolicy.toString(4));
    }

    private static void exitWithErrMsg(String msg) {
        System.out.println(msg);
        System.exit(-1);
    }
}
