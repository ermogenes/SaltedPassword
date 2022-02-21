using System;
using Xunit;
using Ermogenes.SaltedPassword;

namespace Ermogenes.SaltedPassword.Tests;

public class SaltedPasswordTest
{
    [Theory]
    [InlineData("My$upeR Secr37 _123✨")]
    [InlineData("123")]
    [InlineData("ARcxvcsdfSREsfd$REesfdf")]
    [InlineData("_435GdG_tfgnfdgDFGfdgj")]
    public void GetPersistentKey_CreatesKeyInCorrectFormat(string password)
    {
        string key = SaltedPassword.GetPersistentKey(password);
        Assert.IsType<string>(key);

        var keyParts = key.Split("|");
        Assert.IsType<string[]>(keyParts);
        Assert.Equal(3, keyParts.Length);

        int numBytes;
        var buffer0 = new Span<byte>(new byte[keyParts[0].Length]);
        var buffer2 = new Span<byte>(new byte[keyParts[2].Length]);

        Assert.IsType<string>(keyParts[0]);
        Assert.True(Convert.TryFromBase64String(keyParts[0], buffer0, out numBytes));
        Assert.True(numBytes > 0);

        Assert.IsType<int>(Convert.ToInt32(keyParts[1]));
        Assert.InRange<int>(Convert.ToInt32(keyParts[1]), 310000, 320000);

        Assert.IsType<string>(keyParts[2]);
        Assert.True(Convert.TryFromBase64String(keyParts[2], buffer2, out numBytes));
        Assert.True(numBytes > 0);
    }

    [Theory]
    [InlineData("My$upeR Secr37 _123✨")]
    [InlineData("123")]
    [InlineData("ARcxvcsdfSREsfd$REesfdf")]
    [InlineData("_435GdG_tfgnfdgDFGfdgj")]
    public void Match_ReturnsTrueForCorrectPassword(string correctPassword)
    {
        string storedKey = SaltedPassword.GetPersistentKey(correctPassword);
        Assert.True(SaltedPassword.Match(correctPassword, storedKey));
    }

    [Theory]
    [InlineData("My$upeR Secr37 _123✨")]
    [InlineData("123")]
    [InlineData("ARcxvcsdfSREsfd$REesfdf")]
    [InlineData("_435GdG_tfgnfdgDFGfdgj")]
    public void Match_ReturnsFalseForIncorrectPassword(string correctPassword)
    {
        string storedKey = SaltedPassword.GetPersistentKey(correctPassword);
        string incorrectPassword = "abc123";
        Assert.False(SaltedPassword.Match(incorrectPassword, storedKey));
    }
}