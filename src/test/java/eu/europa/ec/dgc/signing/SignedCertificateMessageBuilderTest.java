package eu.europa.ec.dgc.signing;
import au.com.origin.snapshots.SnapshotMatcher;
import au.com.origin.snapshots.junit5.SnapshotExtension;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.junit.jupiter.api.extension.ExtendWith;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

@ExtendWith(SnapshotExtension.class)
public class SignedCertificateMessageBuilderTest {

    @Test
    public void testDefineConstructor() {
        assertNotEquals(new SignedCertificateMessageBuilder(), null);
    }

    @Test
    public void testDefineBasicEncoding() throws IOException, OperatorCreationException {
            X509CertificateHolder cert = getX509CertificateHolder();
            PrivateKey privateKey = new PrivateKey() {
                @Override
                public String getAlgorithm() {
                    return null;
                }

                @Override
                public String getFormat() {
                    return null;
                }

                @Override
                public byte[] getEncoded() {
                    return new byte[0];
                }
            };

            SnapshotMatcher.expect(
                    new SignedCertificateMessageBuilder()
                            .withSigningCertificate(cert, privateKey)
                            .withPayloadCertificate(cert)
                            .toString()
            ).toMatchSnapshot();
    }

    private X509CertificateHolder getX509CertificateHolder() throws OperatorCreationException, IOException {
        AsymmetricCipherKeyPair pair = generateLongFixedKeys();
        AsymmetricKeyParameter pubKey = (AsymmetricKeyParameter)pair.getPublic();
        AsymmetricKeyParameter privKey = (AsymmetricKeyParameter)pair.getPrivate();

        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

        AlgorithmIdentifier sigAlgId = sigAlgFinder.find("MD5withRSA");
        AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privKey);
        BcX509v3CertificateBuilder certGen = new BcX509v3CertificateBuilder(new X500Name("CN=Test"), BigInteger.valueOf(1),new Date(System.currentTimeMillis() - 50000),new Date(System.currentTimeMillis() + 50000),new X500Name("CN=Test"),pubKey);
        X509CertificateHolder cert = certGen.build(sigGen);
        return cert;
    }


    private AsymmetricCipherKeyPair generateLongFixedKeys()
    {
        RSAKeyParameters pubKeySpec = new RSAKeyParameters(
                false,
                new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
                new BigInteger("010001",16));

        RSAKeyParameters privKeySpec = new RSAPrivateCrtKeyParameters(
                new BigInteger("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",16),
                new BigInteger("010001",16),
                new BigInteger("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",16),
                new BigInteger("e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",16),
                new BigInteger("b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",16),
                new BigInteger("28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",16),
                new BigInteger("1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",16),
                new BigInteger("27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",16));

        return new AsymmetricCipherKeyPair(pubKeySpec, privKeySpec);
    }

}
