using System.Security.Cryptography;

namespace Ermogenes.SaltedPassword;
public class SaltedPassword
{
    public static int hashSizeInBytes { get; } = 512 / 8;
    public static int saltSizeInBytes { get; } = 128 / 8;
    public static HashAlgorithmName hashAlgo = HashAlgorithmName.SHA256;
    public static int minIterations { get; } = 310000;
    public static int maxIterationsOverMinLimit { get; } = 10000;

    public static string GetPersistentKey(string password)
    {
        int iterations = minIterations + RandomNumberGenerator.GetInt32(0, maxIterationsOverMinLimit);

        var hashGenerator = new Rfc2898DeriveBytes(password, saltSizeInBytes, iterations, hashAlgo);

        string base64Salt = Convert.ToBase64String(hashGenerator.Salt);
        int iterationCount = hashGenerator.IterationCount;
        string base64Hash = Convert.ToBase64String(hashGenerator.GetBytes(hashSizeInBytes));

        return $"{base64Salt}|{iterationCount}|{base64Hash}";
    }

    public static bool Match(string password, string persistentKey)
    {
        string[] keyParts = persistentKey.Split("|");
        byte[] persistedSalt = Convert.FromBase64String(keyParts[0]);
        int persistedIterations = Convert.ToInt32(keyParts[1]);
        string persistedHash = keyParts[2];

        var hashGenerator = new Rfc2898DeriveBytes(password, persistedSalt, persistedIterations, hashAlgo);

        string hashFromPassword = Convert.ToBase64String(hashGenerator.GetBytes(hashSizeInBytes));

        return persistedHash == hashFromPassword;
    }
}
