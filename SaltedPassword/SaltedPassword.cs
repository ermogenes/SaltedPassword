using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Ermogenes.SaltedPassword;
public class SaltedPassword
{
    public static int HashSizeInBytes { get; } = 512 / 8;
    public static int SaltSizeInBytes { get; } = 128 / 8;
    public static KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA256;
    public static int MinIterations { get; } = 310000;
    public static int MaxIterationsOverMinLimit { get; } = 10000;

    public static string GetPersistentKey(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeInBytes);

        int iterationCount = MinIterations + RandomNumberGenerator.GetInt32(0, MaxIterationsOverMinLimit);

        byte[] hash = KeyDerivation.Pbkdf2(
            password,
            salt,
            PseudoRandomFunction,
            iterationCount,
            HashSizeInBytes
        );

        string base64Salt = Convert.ToBase64String(salt);
        string base64Hash = Convert.ToBase64String(hash);

        return $"{base64Salt}|{iterationCount}|{base64Hash}";
    }

    public static bool Match(string password, string persistentKey)
    {
        string[] keyParts = persistentKey.Split("|");
        byte[] persistentSalt = Convert.FromBase64String(keyParts[0]);
        int persistentIterations = Convert.ToInt32(keyParts[1]);
        string persistentHash = keyParts[2];

        byte[] hashFromPasswordBytes = KeyDerivation.Pbkdf2(
            password,
            persistentSalt,
            PseudoRandomFunction,
            persistentIterations,
            HashSizeInBytes
        );

        string hashFromPassword = Convert.ToBase64String(hashFromPasswordBytes);

        return persistentHash == hashFromPassword;
    }
}
