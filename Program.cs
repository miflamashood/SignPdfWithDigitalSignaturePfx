using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignPdfWithDigitalSignaturePfx;

static class Program
{
    static async Task Main()
    {
        await UsePfxFromFileSystem();
        await UsePfxFromKeyVault();
    }

    private static Task UsePfxFromFileSystem()
    {
        string keystore = "temp.pfx";

        char[] password = "".ToCharArray();
        
        Pkcs12Store pk12 = new Pkcs12Store(new FileStream(keystore,
            FileMode.Open, FileAccess.Read) , password);
        
        string? alias = null;

        foreach (object a in pk12.Aliases)
        {
            alias = ((string)a);

            if (pk12.IsKeyEntry(alias))
            {
                break;
            }
        }

        ICipherParameters pk = pk12.GetKey(alias).Key;
        X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
        X509Certificate[] chain = new X509Certificate[ce.Length];

        for (int k = 0; k < ce.Length; ++k)
        {
            chain[k] = ce[k].Certificate;
        }

        string destination = "Agreement-Signed.pdf";
        string source = "Agreement.pdf";

        PdfReader reader = new PdfReader(source);
        PdfSigner signer = new PdfSigner(reader,
            new FileStream(destination, FileMode.Create),
            new StampingProperties());

        PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
        appearance.SetReason("I'm signing this because ....")
            .SetLocation("Colombo")
            .SetPageRect(new Rectangle(70, 550, 300, 100))
            .SetPageNumber(1);

        signer.SetFieldName("SignatureField");

        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256);

        signer.SignDetached(pks,
            chain,
            null,
            null,
            null,
            0,
            PdfSigner.CryptoStandard.CMS);
        return Task.CompletedTask;
    }
    static async Task UsePfxFromKeyVault()
    {
        char[] password = "".ToCharArray();

        const string certificateName = "temp";
        var keyVaultName = "mn-kv-darknessd11d1e0";
        var kvUri = $"https://{keyVaultName}.vault.azure.net";

        var client = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());

        KeyVaultCertificateWithPolicy certificate = await client.GetCertificateAsync(certificateName);

        var secretClient = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
        
        KeyVaultSecret secret =await secretClient.GetSecretAsync(certificate.SecretId.Segments[2]+certificate.SecretId.Segments[3]);

        byte[] pfx = Convert.FromBase64String(secret.Value);

        Pkcs12Store pk12 = new Pkcs12Store(new MemoryStream(pfx), password);
        
        string? alias = null;

        foreach (object a in pk12.Aliases)
        {
            alias = ((string)a);

            if (pk12.IsKeyEntry(alias))
            {
                break;
            }
        }

        ICipherParameters pk = pk12.GetKey(alias).Key;
        X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
        X509Certificate[] chain = new X509Certificate[ce.Length];

        for (int k = 0; k < ce.Length; ++k)
        {
            chain[k] = ce[k].Certificate;
        }

        string Destination = "SignedAgreement.pdf";
        string Source = "Agreement.pdf";

        PdfReader reader = new PdfReader(Source);
        PdfSigner signer = new PdfSigner(reader,
            new FileStream(Destination, FileMode.Create),
            new StampingProperties());

        PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
        appearance.SetReason("I'm signing this because ....")
            .SetLocation("Colombo")
            .SetPageRect(new Rectangle(70, 558, 200, 100))
            .SetPageNumber(1);

        signer.SetFieldName("SignatureField");

        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256);

        signer.SignDetached(pks,
            chain,
            null,
            null,
            null,
            0,
            PdfSigner.CryptoStandard.CMS);
    }
}