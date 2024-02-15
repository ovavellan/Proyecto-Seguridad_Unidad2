using System.Runtime.InteropServices;
using PInvoke;
using static PInvoke.BCrypt;
using System.Security.Cryptography;

namespace CookiesMaster;

public class AesCrypto
{
    private static readonly Random Rand = new();

    private static readonly byte[] Prefix = { 0x76, 0x31, 0x30 };

    private static readonly int PrefixSize = Prefix.Length;

    private const int NonceSize = 12;

    private const int TagSize = 16;

    private readonly string _localStatePath;

    public readonly byte[] Key;

    public AesCrypto(string localStatePath)
    {
        _localStatePath = localStatePath;
        Key = GetEncryptionKey();
    }


    private static byte[] SubArray(byte[] data, int index, int length)
    {
        var result = new byte[length];
        Array.Copy(data, index, result, 0, length);
        return result;
    }

    private byte[] GetEncryptionKey()
    {
        var localState = File.ReadAllText(_localStatePath);
        var encryptedKey = Utils.RegexComponent.GetEncryptedKey(localState);


        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ProtectedData.Unprotect(
                SubArray(encryptedKey, 5, encryptedKey.Length - 5),
                null, DataProtectionScope.CurrentUser);
        }

        throw new PlatformNotSupportedException("Only Windows is supported");
    }


    private static unsafe byte[] GcmDecrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[]? pbAuthData = null)
    {
        pbAuthData ??= Array.Empty<byte>();

        using var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM);
        BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

        var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

        if (pbTag.Length < tagLengths.dwMinLength
            || pbTag.Length > tagLengths.dwMaxLength
            || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
            throw new ArgumentException("Invalid tag length");

        using var key = BCryptGenerateSymmetricKey(provider, pbKey);

        var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
        fixed (byte* pTagBuffer = pbTag)
        fixed (byte* pNonce = pbNonce)
        fixed (byte* pAuthData = pbAuthData)
        {
            authInfo.pbNonce = pNonce;
            authInfo.cbNonce = pbNonce.Length;
            authInfo.pbTag = pTagBuffer;
            authInfo.cbTag = pbTag.Length;
            authInfo.pbAuthData = pAuthData;
            authInfo.cbAuthData = pbAuthData.Length;

            //Initialize Cipher Text Byte Count
            var pcbPlaintext = pbData.Length;

            //Allocate Plaintext Buffer
            var pbPlaintext = new byte[pcbPlaintext];

            NTSTATUS status;
            fixed (byte* ciphertext = pbData)
            fixed (byte* plaintext = pbPlaintext)
            {
                //Decrypt The Data
                status = BCryptDecrypt(
                    key,
                    ciphertext,
                    pbData.Length,
                    &authInfo,
                    null,
                    0,
                    plaintext,
                    pbPlaintext.Length,
                    out pcbPlaintext,
                    0);
            }


            if (status == NTSTATUS.Code.STATUS_AUTH_TAG_MISMATCH)
            {
                throw new CryptographicException("BCryptDecrypt auth tag mismatch");
            }

            if (status != NTSTATUS.Code.STATUS_SUCCESS)
            {
                throw new CryptographicException($"BCryptDecrypt failed result {status:X} ");
            }

            return pbPlaintext;
        }
    }


    private static unsafe byte[] GcmEncrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag, byte[]? pbAuthData = null)
    {
        pbAuthData ??= Array.Empty<byte>();

        using var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM);

        BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

        var tagLengths = BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

        if (pbTag.Length < tagLengths.dwMinLength
            || pbTag.Length > tagLengths.dwMaxLength
            || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
            throw new ArgumentException("Invalid tag length");

        using (var key = BCryptGenerateSymmetricKey(provider, pbKey))
        {
            var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
            fixed (byte* pTagBuffer = pbTag)
            fixed (byte* pNonce = pbNonce)
            fixed (byte* pAuthData = pbAuthData)
            {
                authInfo.pbNonce = pNonce;
                authInfo.cbNonce = pbNonce.Length;
                authInfo.pbTag = pTagBuffer;
                authInfo.cbTag = pbTag.Length;
                authInfo.pbAuthData = pAuthData;
                authInfo.cbAuthData = pbAuthData.Length;

                //Initialize Cipher Text Byte Count
                var pcbCipherText = pbData.Length;

                //Allocate Cipher Text Buffer
                var pbCipherText = new byte[pcbCipherText];

                NTSTATUS status;
                fixed (byte* plainText = pbData)
                fixed (byte* cipherText = pbCipherText)
                {
                    //Encrypt The Data
                    status = BCryptEncrypt(
                        key,
                        plainText,
                        pbData.Length,
                        &authInfo,
                        null,
                        0,
                        cipherText,
                        pbCipherText.Length,
                        out pcbCipherText,
                        0);
                }

                if (status != NTSTATUS.Code.STATUS_SUCCESS)
                    throw new CryptographicException($"BCryptEncrypt failed result {status:X} ");

                return pbCipherText;
            }
        }
    }

    public byte[] Encrypt(byte[] plainText)
    {
        var pbNonce = new byte[NonceSize];
        Rand.NextBytes(pbNonce);

        var pbTag = new byte[TagSize];
        Rand.NextBytes(pbTag);

        var encryptedBytes = GcmEncrypt(plainText, Key, pbNonce, pbTag);
        var cipherText = new byte[Prefix.Length + NonceSize + encryptedBytes.Length + TagSize];
        Prefix.CopyTo(cipherText, 0);
        pbNonce.CopyTo(cipherText, Prefix.Length);
        encryptedBytes.CopyTo(cipherText, Prefix.Length + pbNonce.Length);
        pbTag.CopyTo(cipherText, Prefix.Length + pbNonce.Length + encryptedBytes.Length);
        return cipherText;
    }

    public byte[] Decrypt(byte[] cipherText)
    {
        var pbNonce = SubArray(cipherText, PrefixSize, NonceSize);
        var pbData = SubArray(cipherText, PrefixSize + NonceSize, cipherText.Length - NonceSize - PrefixSize - TagSize);
        var pbTag = SubArray(cipherText, PrefixSize + NonceSize + pbData.Length, TagSize);
        return GcmDecrypt(pbData, Key, pbNonce, pbTag);
    }
}